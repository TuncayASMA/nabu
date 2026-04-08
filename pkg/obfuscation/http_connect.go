// Package obfuscation provides transport.Layer implementations that disguise
// NABU traffic to bypass Deep Packet Inspection (DPI) firewalls.
//
// HTTPConnect wraps NABU frames inside a plain TCP stream established through
// an HTTP/1.1 CONNECT tunnel.  From the network's perspective the connection
// looks like ordinary HTTPS traffic: the client sends an HTTP CONNECT request
// to the relay's HTTP port; once the relay responds "200 Connection established",
// both sides speak the NABU binary framing protocol over that TCP pipe.
//
// Frame framing over TCP uses a 4-byte big-endian length prefix:
//
// ┌──────────────────┬───────────────────────────┐
// │  Length (4 B BE) │  NABU Frame (N bytes)     │
// └──────────────────┴───────────────────────────┘
package obfuscation

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

const (
	DefaultTCPDialTimeout  = 10 * time.Second
	DefaultTCPReadTimeout  = 5 * time.Second
	DefaultTCPWriteTimeout = 5 * time.Second
)

// HTTPConnect implements transport.Layer by tunnelling NABU frames over a TCP
// connection opened via an HTTP/1.1 CONNECT request.
type HTTPConnect struct {
	RelayAddr    string
	ProxyAddr    string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	SessionKey   []byte

	conn   net.Conn
	reader *bufio.Reader
}

var _ transport.Layer = (*HTTPConnect)(nil)
var _ transport.ReadTimeoutSetter = (*HTTPConnect)(nil)
var _ transport.SessionKeySetter = (*HTTPConnect)(nil)

// NewHTTPConnect returns an HTTPConnect with sensible defaults.
func NewHTTPConnect(relayAddr, proxyAddr string) (*HTTPConnect, error) {
	if relayAddr == "" {
		return nil, fmt.Errorf("relay address cannot be empty")
	}
	return &HTTPConnect{
		RelayAddr:    relayAddr,
		ProxyAddr:    proxyAddr,
		DialTimeout:  DefaultTCPDialTimeout,
		ReadTimeout:  DefaultTCPReadTimeout,
		WriteTimeout: DefaultTCPWriteTimeout,
	}, nil
}

// SetReadTimeout implements transport.ReadTimeoutSetter.
func (h *HTTPConnect) SetReadTimeout(d time.Duration) { h.ReadTimeout = d }

// SetSessionKey implements transport.SessionKeySetter.
func (h *HTTPConnect) SetSessionKey(key []byte) { h.SessionKey = key }

// Connect dials the underlying TCP connection and (when ProxyAddr is set)
// issues an HTTP/1.1 CONNECT handshake.
func (h *HTTPConnect) Connect() error {
	dialTarget := h.RelayAddr
	if h.ProxyAddr != "" {
		dialTarget = h.ProxyAddr
	}
	dialer := &net.Dialer{Timeout: h.DialTimeout}
	conn, err := dialer.Dial("tcp", dialTarget)
	if err != nil {
		return fmt.Errorf("tcp dial %s failed: %w", dialTarget, err)
	}
	if h.ProxyAddr != "" {
		if err := h.httpConnectHandshake(conn); err != nil {
			_ = conn.Close()
			return err
		}
	}
	h.conn = conn
	h.reader = bufio.NewReader(conn)
	return nil
}

// httpConnectHandshake sends HTTP CONNECT and validates the 200 response.
func (h *HTTPConnect) httpConnectHandshake(conn net.Conn) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: h.RelayAddr},
		Host:   h.RelayAddr,
		Header: http.Header{
			"User-Agent":       {"Mozilla/5.0 (compatible; nabu/1.0)"},
			"Proxy-Connection": {"keep-alive"},
		},
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("write CONNECT request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CONNECT rejected: %d %s", resp.StatusCode, resp.Status)
	}
	return nil
}

// Close closes the underlying TCP connection.
func (h *HTTPConnect) Close() error {
	if h.conn == nil {
		return nil
	}
	return h.conn.Close()
}

// SendFrame encodes f as a length-prefixed NABU frame and writes it to the TCP stream.
func (h *HTTPConnect) SendFrame(f transport.Frame) error {
	if h.conn == nil {
		return fmt.Errorf("http-connect transport not connected")
	}
	if len(h.SessionKey) > 0 && len(f.Payload) > 0 && f.Flags&transport.FlagHandshake == 0 {
		enc, err := encryptPayload(f.Payload, h.SessionKey)
		if err != nil {
			return fmt.Errorf("frame encrypt failed: %w", err)
		}
		f.Payload = enc
	}
	raw, err := transport.EncodeFrame(f)
	if err != nil {
		return err
	}
	if err := h.conn.SetWriteDeadline(time.Now().Add(h.WriteTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	if _, err := h.conn.Write(hdr[:]); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := h.conn.Write(raw); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// ReceiveFrame reads one length-prefixed NABU frame from the TCP stream.
func (h *HTTPConnect) ReceiveFrame() (transport.Frame, error) {
	if h.conn == nil {
		return transport.Frame{}, fmt.Errorf("http-connect transport not connected")
	}
	if err := h.conn.SetReadDeadline(time.Now().Add(h.ReadTimeout)); err != nil {
		return transport.Frame{}, fmt.Errorf("set read deadline: %w", err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(h.reader, hdr[:]); err != nil {
		return transport.Frame{}, fmt.Errorf("read length prefix: %w", err)
	}
	frameLen := binary.BigEndian.Uint32(hdr[:])
	if frameLen == 0 || frameLen > uint32(transport.MaxPayload+transport.HeaderSize) {
		return transport.Frame{}, fmt.Errorf("invalid frame length %d", frameLen)
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(h.reader, buf); err != nil {
		return transport.Frame{}, fmt.Errorf("read frame body: %w", err)
	}
	frame, err := transport.DecodeFrame(buf)
	if err != nil {
		return transport.Frame{}, err
	}
	if len(h.SessionKey) > 0 && len(frame.Payload) > 0 && frame.Flags&transport.FlagHandshake == 0 {
		dec, err := decryptPayload(frame.Payload, h.SessionKey)
		if err != nil {
			return transport.Frame{}, fmt.Errorf("frame decrypt: %w", err)
		}
		frame.Payload = dec
	}
	return frame, nil
}
