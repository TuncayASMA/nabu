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
	return NewRelayHandlerWithLayer(relayAddr, psk, nil)
}

// NewRelayHandlerWithLayer is like NewRelayHandler but accepts a pre-built
// transport.Layer. When layer is nil (or the layer does not implement a
// Connect method), the handler falls back to a fresh UDP connection per
// SOCKS5 request. When layer is non-nil it is used as-is for every request
// (it must already be connected).
func NewRelayHandlerWithLayer(relayAddr string, psk []byte, layer transport.Layer) socks5.ConnHandler {
	return func(conn net.Conn, req socks5.Request) error {
		var l transport.Layer
		if layer != nil {
			l = layer
		} else {
			udpClient, err := transport.NewUDPClient(relayAddr)
			if err != nil {
				return fmt.Errorf("create udp client failed: %w", err)
			}
			defer udpClient.Close()

			if err := udpClient.Connect(); err != nil {
				return fmt.Errorf("connect udp client failed: %w", err)
			}
			l = udpClient
		}

		return runTunnel(conn, req, l, psk)
	}
}

// NewRelayHandlerUDPSalamander creates a handler that uses direct UDP
// transport with Salamander obfuscation enabled. salamanderPSK must match the
// relay's configured PSK; if empty, Salamander is disabled (same as
// NewRelayHandler). This handler always uses the UDP path; it is incompatible
// with TCP-based obfuscation layers.
func NewRelayHandlerUDPSalamander(relayAddr string, psk []byte, salamanderPSK []byte) socks5.ConnHandler {
	return func(conn net.Conn, req socks5.Request) error {
		udpClient, err := transport.NewUDPClient(relayAddr)
		if err != nil {
			return fmt.Errorf("create udp client failed: %w", err)
		}
		defer udpClient.Close()

		if len(salamanderPSK) > 0 {
			udpClient.SalamanderPSK = salamanderPSK
		}

		if err := udpClient.Connect(); err != nil {
			return fmt.Errorf("connect udp client failed: %w", err)
		}
		return runTunnel(conn, req, udpClient, psk)
	}
}

// NewRelayHandlerWithFactory returns a ConnHandler that calls layerFactory on
// every inbound SOCKS5 connection to obtain a fresh, already-connected
// transport.Layer. This is the correct approach when the obfuscation layer is
// a TCP connection (e.g. HTTPConnect) that cannot be multiplexed across
// concurrent SOCKS5 sessions.
func NewRelayHandlerWithFactory(psk []byte, layerFactory func() (transport.Layer, error)) socks5.ConnHandler {
	return func(conn net.Conn, req socks5.Request) error {
		l, err := layerFactory()
		if err != nil {
			return fmt.Errorf("create transport layer failed: %w", err)
		}
		defer l.Close()
		return runTunnel(conn, req, l, psk)
	}
}

// runTunnel executes the full tunnel lifecycle on the given transport Layer.
// Separating this from NewRelayHandler makes it testable with any Layer
// implementation (e.g., a future obfuscation wrapper).
func runTunnel(conn net.Conn, req socks5.Request, layer transport.Layer, psk []byte) error {
	// PSK handshake: derive session key before sending any application frame.
	if len(psk) > 0 {
		if err := performHandshake(layer, psk); err != nil {
			return fmt.Errorf("handshake failed: %w", err)
		}
	}

	// Measure RTT to use as the base for adaptive retry timeouts.
	// Fall back to defaultAckTimeout if the ping fails (e.g., relay too old).
	streamID := uint16(atomic.AddUint32(&nextStreamID, 1))
	baseTimeout := defaultAckTimeout
	if measurer, ok := layer.(transport.RTTMeasurer); ok {
		if rtt, rttErr := measurer.MeasureRTT(streamID, 0); rttErr == nil && rtt > 0 {
			baseTimeout = rtt*2 + rttSlop
			if baseTimeout < minRTTBackoff {
				baseTimeout = minRTTBackoff
			}
			if baseTimeout > maxRTTBackoff {
				baseTimeout = maxRTTBackoff
			}
		}
	}

	connectSeq := uint32(1)
	if err := layer.SendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: streamID,
		Seq:      connectSeq,
		Payload:  []byte(net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))),
	}); err != nil {
		return fmt.Errorf("send connect frame failed: %w", err)
	}

	if ts, ok := layer.(transport.ReadTimeoutSetter); ok {
		ts.SetReadTimeout(baseTimeout)
	}

	if err := waitForAck(layer, streamID, connectSeq); err != nil {
		return fmt.Errorf("wait for connect ack failed: %w", err)
	}

	resultCh := make(chan error, 2)
	ackCh := make(chan uint32, 64)
	var once sync.Once
	shutdown := func(err error) {
		once.Do(func() {
			_ = layer.Close()
			resultCh <- err
		})
	}

	go pipeConnToRelay(conn, layer, streamID, ackCh, baseTimeout, shutdown)
	go pipeRelayToConn(conn, layer, streamID, ackCh, shutdown)

	if err := <-resultCh; err != nil && err != io.EOF {
		return err
	}
	return nil
}

// performHandshake executes the X25519 key exchange with the relay.
//
// Protocol:
//  1. Generate ephemeral X25519 key pair.
//  2. Send FlagHandshake frame with Payload = clientPublicKey (32 B).
//  3. Wait for relay's FlagHandshake|FlagACK with Payload = relayPublicKey (32 B).
//  4. Compute shared secret and derive session key.
//  5. Set UDPClient.SessionKey — all subsequent frames will be encrypted.
func performHandshake(client transport.Layer, psk []byte) error {
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

	if ts, ok := client.(transport.ReadTimeoutSetter); ok {
		ts.SetReadTimeout(defaultAckTimeout)
	}

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
	// UDPClient implements this directly; obfuscation wrappers must proxy it.
	if udp, ok := client.(*transport.UDPClient); ok {
		udp.SessionKey = key
	}
	return nil
}

func waitForAck(client transport.Layer, streamID uint16, seq uint32) error {
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

func sendFrameWithRetry(client transport.Layer, frame transport.Frame, ackCh <-chan uint32, baseTimeout time.Duration) error {
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
		case ackSeq, ok := <-ackCh:
			if !ok {
				return fmt.Errorf("ack channel closed for seq=%d", expectedSeq)
			}
			if ackSeq == expectedSeq {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("ack timeout for seq=%d", expectedSeq)
		}
	}
}

func pipeConnToRelay(conn net.Conn, client transport.Layer, streamID uint16, ackCh <-chan uint32, baseTimeout time.Duration, shutdown func(error)) {
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

func pipeRelayToConn(conn net.Conn, client transport.Layer, streamID uint16, ackCh chan<- uint32, shutdown func(error)) {
	defer close(ackCh)

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
