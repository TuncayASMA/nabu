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
