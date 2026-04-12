package transport

import (
	"fmt"
	"net"
	"sync"
	"time"

	nabuCrypto "github.com/TuncayASMA/nabu/pkg/crypto"
)

const (
	DefaultUDPWriteTimeout = 2 * time.Second
	DefaultUDPReadTimeout  = 5 * time.Second
	DefaultUDPSocketBuffer = 4 * 1024 * 1024
)

type UDPClient struct {
	mu           sync.RWMutex
	RelayAddr    string
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	ReadBuffer   int
	WriteBuffer  int
	// SessionKey enables AES-256-GCM frame encryption when set (32 bytes).
	// Populated after a successful PSK handshake.
	SessionKey []byte
	// SalamanderPSK, when non-nil, wraps every outgoing UDP datagram in a
	// Salamander envelope and decodes incoming datagrams before processing.
	// Must match the relay's SalamanderPSK.
	SalamanderPSK []byte
	conn          *net.UDPConn
	nextPacketSeq uint16
}

// Compile-time assertions: UDPClient must satisfy both Layer and RTTMeasurer.
var _ Layer = (*UDPClient)(nil)
var _ RTTMeasurer = (*UDPClient)(nil)
var _ ReadTimeoutSetter = (*UDPClient)(nil)

// SetReadTimeout adjusts the per-receive-call deadline used by ReceiveFrame.
// It satisfies the ReadTimeoutSetter optional interface.
func (c *UDPClient) SetReadTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ReadTimeout = d
}

func NewUDPClient(relayAddr string) (*UDPClient, error) {
	if relayAddr == "" {
		return nil, fmt.Errorf("relay address cannot be empty")
	}
	return &UDPClient{
		RelayAddr:    relayAddr,
		WriteTimeout: DefaultUDPWriteTimeout,
		ReadTimeout:  DefaultUDPReadTimeout,
		ReadBuffer:   DefaultUDPSocketBuffer,
		WriteBuffer:  DefaultUDPSocketBuffer,
	}, nil
}

func (c *UDPClient) Connect() error {
	addr, err := net.ResolveUDPAddr("udp", c.RelayAddr)
	if err != nil {
		return fmt.Errorf("resolve relay addr failed: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("dial udp failed: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	readBuf := c.ReadBuffer
	writeBuf := c.WriteBuffer
	c.mu.Unlock()

	if readBuf > 0 {
		if err := conn.SetReadBuffer(readBuf); err != nil {
			return fmt.Errorf("set read buffer failed: %w", err)
		}
	}
	if writeBuf > 0 {
		if err := conn.SetWriteBuffer(writeBuf); err != nil {
			return fmt.Errorf("set write buffer failed: %w", err)
		}
	}
	return nil
}

func (c *UDPClient) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()

	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (c *UDPClient) SendFrame(f Frame) error {
	c.mu.RLock()
	conn := c.conn
	writeTimeout := c.WriteTimeout
	sessionKey := append([]byte(nil), c.SessionKey...)
	salamanderPSK := append([]byte(nil), c.SalamanderPSK...)
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("udp client not connected")
	}
	// Encrypt payload for non-handshake frames when session key is set.
	if len(sessionKey) == nabuCrypto.AES256KeySize && len(f.Payload) > 0 && (f.Flags&FlagHandshake == 0) {
		enc, err := nabuCrypto.Encrypt(f.Payload, sessionKey)
		if err != nil {
			return fmt.Errorf("frame encrypt failed: %w", err)
		}
		f.Payload = enc
	}
	raw, err := EncodeFrame(f)
	if err != nil {
		return err
	}
	// Wrap with Salamander outer obfuscation when enabled.
	if len(salamanderPSK) > 0 {
		raw, err = nabuCrypto.SalamanderEncode(salamanderPSK, raw)
		if err != nil {
			return fmt.Errorf("salamander encode: %w", err)
		}
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("set write deadline failed: %w", err)
	}
	_, err = conn.Write(raw)
	if err != nil {
		return fmt.Errorf("udp write failed: %w", err)
	}
	return nil
}

func (c *UDPClient) ReceiveFrame() (Frame, error) {
	c.mu.RLock()
	conn := c.conn
	readTimeout := c.ReadTimeout
	sessionKey := append([]byte(nil), c.SessionKey...)
	salamanderPSK := append([]byte(nil), c.SalamanderPSK...)
	c.mu.RUnlock()

	if conn == nil {
		return Frame{}, fmt.Errorf("udp client not connected")
	}

	buf := make([]byte, HeaderSize+MaxPayload)
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return Frame{}, fmt.Errorf("set read deadline failed: %w", err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		return Frame{}, fmt.Errorf("udp read failed: %w", err)
	}
	packet := buf[:n]
	// Unwrap Salamander outer obfuscation when enabled.
	if len(salamanderPSK) > 0 {
		packet, err = nabuCrypto.SalamanderDecode(salamanderPSK, packet)
		if err != nil {
			return Frame{}, fmt.Errorf("salamander decode: %w", err)
		}
	}
	frame, err := DecodeFrame(packet)
	if err != nil {
		return Frame{}, err
	}
	// Decrypt payload for non-handshake frames when session key is set.
	if len(sessionKey) == nabuCrypto.AES256KeySize && len(frame.Payload) > 0 && (frame.Flags&FlagHandshake == 0) {
		dec, err := nabuCrypto.Decrypt(frame.Payload, sessionKey)
		if err != nil {
			return Frame{}, fmt.Errorf("frame decrypt failed: %w", err)
		}
		frame.Payload = dec
	}
	return frame, nil
}

// SendPacket encodes and transmits a packet-level datagram.
func (c *UDPClient) SendPacket(p Packet) error {
	c.mu.RLock()
	conn := c.conn
	writeTimeout := c.WriteTimeout
	salamanderPSK := append([]byte(nil), c.SalamanderPSK...)
	c.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("udp client not connected")
	}

	c.mu.Lock()
	// Keep the sequence allocator monotonic even when caller sets Seq explicitly.
	if p.Seq >= c.nextPacketSeq {
		c.nextPacketSeq = p.Seq + 1
	}
	c.mu.Unlock()

	raw, err := EncodePacket(p)
	if err != nil {
		return err
	}
	if len(salamanderPSK) > 0 {
		raw, err = nabuCrypto.SalamanderEncode(salamanderPSK, raw)
		if err != nil {
			return fmt.Errorf("salamander encode: %w", err)
		}
	}

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("set write deadline failed: %w", err)
	}
	if _, err := conn.Write(raw); err != nil {
		return fmt.Errorf("udp write failed: %w", err)
	}
	return nil
}

// ReceivePacket blocks until one packet-level datagram arrives or deadline expires.
func (c *UDPClient) ReceivePacket() (Packet, error) {
	c.mu.RLock()
	conn := c.conn
	readTimeout := c.ReadTimeout
	salamanderPSK := append([]byte(nil), c.SalamanderPSK...)
	c.mu.RUnlock()

	if conn == nil {
		return Packet{}, fmt.Errorf("udp client not connected")
	}

	buf := make([]byte, PacketHeaderSize+MaxUDPPayload+PacketCRCSize)
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return Packet{}, fmt.Errorf("set read deadline failed: %w", err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		return Packet{}, fmt.Errorf("udp read failed: %w", err)
	}
	raw := buf[:n]
	if len(salamanderPSK) > 0 {
		raw, err = nabuCrypto.SalamanderDecode(salamanderPSK, raw)
		if err != nil {
			return Packet{}, fmt.Errorf("salamander decode: %w", err)
		}
	}

	p, err := DecodePacket(raw)
	if err != nil {
		return Packet{}, err
	}
	return p, nil
}

// SendPayloadFragments splits payload into MTU-safe chunks and sends them with
// monotonically increasing sequence numbers.
func (c *UDPClient) SendPayloadFragments(flags byte, timestamp uint32, payload []byte) (int, error) {
	chunks := FragmentPayload(payload, MaxUDPPayload)
	if len(chunks) == 0 {
		return 0, nil
	}

	seqs := make([]uint16, len(chunks))
	c.mu.Lock()
	for i := range chunks {
		seqs[i] = c.nextPacketSeq
		c.nextPacketSeq++
	}
	c.mu.Unlock()

	for i, chunk := range chunks {
		pkt := Packet{
			Seq:       seqs[i],
			Flags:     flags,
			Timestamp: timestamp,
			Payload:   chunk,
		}
		if err := c.SendPacket(pkt); err != nil {
			return i, err
		}
	}

	return len(chunks), nil
}

// MeasureRTT sends a single Ping frame and waits for the matching Pong reply.
// It returns the round-trip time or an error if the exchange times out.
// The caller should use a deadline-aware context or set ReadTimeout accordingly.
func (c *UDPClient) MeasureRTT(streamID uint16, seq uint32) (time.Duration, error) {
	if c.conn == nil {
		return 0, fmt.Errorf("udp client not connected")
	}

	ping := Frame{
		Version:  FrameVersion,
		Flags:    FlagPing,
		StreamID: streamID,
		Seq:      seq,
	}

	start := time.Now()
	if err := c.SendFrame(ping); err != nil {
		return 0, fmt.Errorf("ping send failed: %w", err)
	}

	// Drain frames until we see the matching Pong.
	deadline := time.Now().Add(c.ReadTimeout)
	for time.Now().Before(deadline) {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return 0, fmt.Errorf("set read deadline: %w", err)
		}
		buf := make([]byte, HeaderSize+MaxPayload)
		n, err := c.conn.Read(buf)
		if err != nil {
			return 0, fmt.Errorf("pong read failed: %w", err)
		}
		raw := buf[:n]
		// Unwrap Salamander when enabled — MeasureRTT bypasses ReceiveFrame so
		// we must apply the same decoding here to avoid an infinite skip-loop.
		if len(c.SalamanderPSK) > 0 {
			decoded, decErr := nabuCrypto.SalamanderDecode(c.SalamanderPSK, raw)
			if decErr != nil {
				continue // Salamander auth failed → skip
			}
			raw = decoded
		}
		f, err := DecodeFrame(raw)
		if err != nil {
			continue // skip malformed frame
		}
		if f.Flags&FlagPong != 0 && f.Ack == seq {
			return time.Since(start), nil
		}
	}
	return 0, fmt.Errorf("pong timeout after %v", c.ReadTimeout)
}
