package tunnel

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	nabuCrypto "github.com/TuncayASMA/nabu/pkg/crypto"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

const clientChunkSize = 1300

const (
	defaultAckTimeout = 1200 * time.Millisecond
	maxSendRetries    = 3
	minRTTBackoff     = 100 * time.Millisecond
	maxRTTBackoff     = 4 * time.Second
	rttSlop           = 50 * time.Millisecond // safety margin added to raw RTT
)

var nextStreamID uint32

func NewRelayHandler(relayAddr string, psk []byte) socks5.ConnHandler {
	return func(conn net.Conn, req socks5.Request) error {
		udpClient, err := transport.NewUDPClient(relayAddr)
		if err != nil {
			return fmt.Errorf("create udp client failed: %w", err)
		}
		defer udpClient.Close()

		if err := udpClient.Connect(); err != nil {
			return fmt.Errorf("connect udp client failed: %w", err)
		}

		// PSK handshake: derive session key before sending any application frame.
		if len(psk) > 0 {
			if err := performHandshake(udpClient, psk); err != nil {
				return fmt.Errorf("handshake failed: %w", err)
			}
		}

		// Measure RTT to use as the base for adaptive retry timeouts.
		// Fall back to defaultAckTimeout if the ping fails (e.g., relay too old).
		streamID := uint16(atomic.AddUint32(&nextStreamID, 1))
		baseTimeout := defaultAckTimeout
		if rtt, rttErr := udpClient.MeasureRTT(streamID, 0); rttErr == nil && rtt > 0 {
			baseTimeout = rtt*2 + rttSlop
			if baseTimeout < minRTTBackoff {
				baseTimeout = minRTTBackoff
			}
			if baseTimeout > maxRTTBackoff {
				baseTimeout = maxRTTBackoff
			}
		}

		connectSeq := uint32(1)
		if err := udpClient.SendFrame(transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagConnect,
			StreamID: streamID,
			Seq:      connectSeq,
			Payload:  []byte(net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))),
		}); err != nil {
			return fmt.Errorf("send connect frame failed: %w", err)
		}

		prevReadTimeout := udpClient.ReadTimeout
		udpClient.ReadTimeout = baseTimeout
		defer func() {
			udpClient.ReadTimeout = prevReadTimeout
		}()

		if err := waitForAck(udpClient, streamID, connectSeq); err != nil {
			return fmt.Errorf("wait for connect ack failed: %w", err)
		}

		resultCh := make(chan error, 2)
		ackCh := make(chan uint32, 64)
		var once sync.Once
		shutdown := func(err error) {
			once.Do(func() {
				_ = udpClient.Close()
				resultCh <- err
			})
		}

		go pipeConnToRelay(conn, udpClient, streamID, ackCh, baseTimeout, shutdown)
		go pipeRelayToConn(conn, udpClient, streamID, ackCh, shutdown)

		if err := <-resultCh; err != nil && err != io.EOF {
			return err
		}
		return nil
	}
}

// performHandshake executes the X25519 key exchange with the relay.
//
// Protocol:
//  1. Generate ephemeral X25519 key pair.
//  2. Send FlagHandshake frame with Payload = clientPublicKey (32 B).
//  3. Wait for relay's FlagHandshake|FlagACK with Payload = relayPublicKey (32 B).
//  4. Compute shared secret and derive session key.
//  5. Set UDPClient.SessionKey — all subsequent frames will be encrypted.
func performHandshake(client *transport.UDPClient, psk []byte) error {
	kp, err := nabuCrypto.GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("client keygen failed: %w", err)
	}

	if err := client.SendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagHandshake,
		StreamID: 0,
		Seq:      1,
		Payload:  kp.Public[:],
	}); err != nil {
		return fmt.Errorf("send handshake frame failed: %w", err)
	}

	prev := client.ReadTimeout
	client.ReadTimeout = defaultAckTimeout
	defer func() { client.ReadTimeout = prev }()

	var relayPub []byte
	for {
		frame, err := client.ReceiveFrame()
		if err != nil {
			return fmt.Errorf("receive handshake ack failed: %w", err)
		}
		if frame.Flags&transport.FlagHandshake != 0 && frame.Flags&transport.FlagACK != 0 {
			relayPub = frame.Payload
			break
		}
	}

	if len(relayPub) != nabuCrypto.X25519PublicKeySize {
		return fmt.Errorf("handshake ack: bad relay pubkey length %d", len(relayPub))
	}

	shared, err := nabuCrypto.X25519SharedSecret(kp.Private[:], relayPub)
	if err != nil {
		return fmt.Errorf("X25519 shared secret failed: %w", err)
	}

	key, err := nabuCrypto.DeriveSessionKeyX25519(psk, shared, kp.Public[:], relayPub)
	if err != nil {
		return fmt.Errorf("derive session key failed: %w", err)
	}
	client.SessionKey = key
	return nil
}

func waitForAck(client *transport.UDPClient, streamID uint16, seq uint32) error {
	for {
		frame, err := client.ReceiveFrame()
		if err != nil {
			return err
		}
		if frame.StreamID != streamID {
			continue
		}
		if frame.Flags&transport.FlagACK != 0 && frame.Ack == seq {
			return nil
		}
		if frame.Flags&transport.FlagFIN != 0 {
			return fmt.Errorf("relay closed stream during connect")
		}
	}
}

func sendFrameWithRetry(client *transport.UDPClient, frame transport.Frame, ackCh <-chan uint32, baseTimeout time.Duration) error {
	backoff := baseTimeout
	if backoff < minRTTBackoff {
		backoff = minRTTBackoff
	}
	var lastErr error
	for attempt := 0; attempt < maxSendRetries; attempt++ {
		if err := client.SendFrame(frame); err != nil {
			lastErr = err
			time.Sleep(backoff)
			backoff = min(backoff*2, maxRTTBackoff)
			continue
		}

		if err := waitForAckSeq(ackCh, frame.Seq, backoff); err != nil {
			lastErr = err
			backoff = min(backoff*2, maxRTTBackoff)
			continue
		}

		return nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("send frame retry exhausted")
	}
	return lastErr
}

func waitForAckSeq(ackCh <-chan uint32, expectedSeq uint32, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case ackSeq := <-ackCh:
			if ackSeq == expectedSeq {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("ack timeout for seq=%d", expectedSeq)
		}
	}
}

func pipeConnToRelay(conn net.Conn, client *transport.UDPClient, streamID uint16, ackCh <-chan uint32, baseTimeout time.Duration, shutdown func(error)) {
	buf := make([]byte, clientChunkSize)
	seq := uint32(2)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			if sendErr := sendFrameWithRetry(client, transport.Frame{
				Version:  transport.FrameVersion,
				Flags:    transport.FlagData,
				StreamID: streamID,
				Seq:      seq,
				Payload:  payload,
			}, ackCh, baseTimeout); sendErr != nil {
				shutdown(fmt.Errorf("send data frame failed: %w", sendErr))
				return
			}
			seq++
		}

		if err != nil {
			if err == io.EOF {
				if sendErr := client.SendFrame(transport.Frame{
					Version:  transport.FrameVersion,
					Flags:    transport.FlagFIN,
					StreamID: streamID,
					Seq:      seq,
				}); sendErr != nil {
					shutdown(fmt.Errorf("send fin frame failed: %w", sendErr))
					return
				}
			}
			shutdown(err)
			return
		}
	}
}

func pipeRelayToConn(conn net.Conn, client *transport.UDPClient, streamID uint16, ackCh chan<- uint32, shutdown func(error)) {
	for {
		frame, err := client.ReceiveFrame()
		if err != nil {
			shutdown(fmt.Errorf("receive relay frame failed: %w", err))
			return
		}
		if frame.StreamID != streamID {
			continue
		}
		if frame.Flags&transport.FlagACK != 0 {
			ackCh <- frame.Ack
			continue
		}
		if frame.Flags&transport.FlagFIN != 0 {
			if err := client.SendFrame(transport.Frame{
				Version:  transport.FrameVersion,
				Flags:    transport.FlagACK,
				StreamID: streamID,
				Ack:      frame.Seq,
			}); err != nil {
				shutdown(fmt.Errorf("send fin ack failed: %w", err))
				return
			}
			shutdown(nil)
			return
		}
		if frame.Flags&transport.FlagData == 0 {
			continue
		}
		if _, err := conn.Write(frame.Payload); err != nil {
			shutdown(fmt.Errorf("write to socks connection failed: %w", err))
			return
		}
	}
}