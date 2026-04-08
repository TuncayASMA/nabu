package transport

import (
	"fmt"
	"net"
	"time"

	nabuCrypto "github.com/TuncayASMA/nabu/pkg/crypto"
)

const (
	DefaultUDPWriteTimeout = 2 * time.Second
	DefaultUDPReadTimeout  = 5 * time.Second
)

type UDPClient struct {
	RelayAddr    string
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	// SessionKey enables AES-256-GCM frame encryption when set (32 bytes).
	// Populated after a successful PSK handshake.
	SessionKey []byte
	conn       *net.UDPConn
}

// Compile-time assertions: UDPClient must satisfy both Layer and RTTMeasurer.
var _ Layer = (*UDPClient)(nil)
var _ RTTMeasurer = (*UDPClient)(nil)
var _ ReadTimeoutSetter = (*UDPClient)(nil)

// SetReadTimeout adjusts the per-receive-call deadline used by ReceiveFrame.
// It satisfies the ReadTimeoutSetter optional interface.
func (c *UDPClient) SetReadTimeout(d time.Duration) {
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
	c.conn = conn
	return nil
}

func (c *UDPClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *UDPClient) SendFrame(f Frame) error {
	if c.conn == nil {
		return fmt.Errorf("udp client not connected")
	}
	// Encrypt payload for non-handshake frames when session key is set.
	if len(c.SessionKey) == nabuCrypto.AES256KeySize && len(f.Payload) > 0 && (f.Flags&FlagHandshake == 0) {
		enc, err := nabuCrypto.Encrypt(f.Payload, c.SessionKey)
		if err != nil {
			return fmt.Errorf("frame encrypt failed: %w", err)
		}
		f.Payload = enc
	}
	raw, err := EncodeFrame(f)
	if err != nil {
		return err
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline failed: %w", err)
	}
	_, err = c.conn.Write(raw)
	if err != nil {
		return fmt.Errorf("udp write failed: %w", err)
	}
	return nil
}

func (c *UDPClient) ReceiveFrame() (Frame, error) {
	if c.conn == nil {
		return Frame{}, fmt.Errorf("udp client not connected")
	}

	buf := make([]byte, HeaderSize+MaxPayload)
	if err := c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout)); err != nil {
		return Frame{}, fmt.Errorf("set read deadline failed: %w", err)
	}
	n, err := c.conn.Read(buf)
	if err != nil {
		return Frame{}, fmt.Errorf("udp read failed: %w", err)
	}
	frame, err := DecodeFrame(buf[:n])
	if err != nil {
		return Frame{}, err
	}
	// Decrypt payload for non-handshake frames when session key is set.
	if len(c.SessionKey) == nabuCrypto.AES256KeySize && len(frame.Payload) > 0 && (frame.Flags&FlagHandshake == 0) {
		dec, err := nabuCrypto.Decrypt(frame.Payload, c.SessionKey)
		if err != nil {
			return Frame{}, fmt.Errorf("frame decrypt failed: %w", err)
		}
		frame.Payload = dec
	}
	return frame, nil
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
		f, err := DecodeFrame(buf[:n])
		if err != nil {
			continue // skip malformed frame
		}
		if f.Flags&FlagPong != 0 && f.Ack == seq {
			return time.Since(start), nil
		}
	}
	return 0, fmt.Errorf("pong timeout after %v", c.ReadTimeout)
}
