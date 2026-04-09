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
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

const (
	DefaultTCPDialTimeout  = 10 * time.Second
	DefaultTCPReadTimeout  = 5 * time.Second
	DefaultTCPWriteTimeout = 5 * time.Second
)

// HTTPConnect implements transport.Layer by tunnelling NABU frames over a TCP
// connection opened via an HTTP/1.1 CONNECT request.
//
// When RelayTLSConfig is non-nil, the underlying TCP dial is upgraded to TLS
// (i.e. a tls.Conn is established before any HTTP CONNECT handshake).  From
// the wire's perspective the connection is indistinguishable from standard
// HTTPS/TLS traffic.
type HTTPConnect struct {
	RelayAddr    string
	ProxyAddr    string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	SessionKey   []byte
	// RelayTLSConfig, when non-nil, wraps the TCP connection with TLS before
	// sending any NABU frame.  Set InsecureSkipVerify for self-signed relay certs.
	RelayTLSConfig *tls.Config

	// UTLSEnabled, when true, replaces the standard Go TLS dialer with a uTLS
	// dialer that mimics the ClientHello of a real browser (Chrome by default).
	// This prevents TLS fingerprinting by DPI engines.  RelayTLSConfig.InsecureSkipVerify
	// is forwarded to the uTLS handshake when RelayTLSConfig is non-nil.
	// UTLSEnabled has no effect when RelayTLSConfig is nil (plain TCP).
	UTLSEnabled bool

	// UTLSFingerprint selects the browser fingerprint (case-insensitive).
	// Valid values: chrome (default), firefox, safari, edge, golang, random.
	// Ignored when UTLSEnabled is false.
	UTLSFingerprint string

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

// WrapConn wraps an already-connected net.Conn into an HTTPConnect layer.
// No TCP dial or HTTP CONNECT handshake is performed — the caller is
// responsible for having established and negotiated the connection.
// This is useful when the outer transport (e.g. TLS) is handled externally.
func WrapConn(c net.Conn) *HTTPConnect {
	return &HTTPConnect{
		ReadTimeout:  DefaultTCPReadTimeout,
		WriteTimeout: DefaultTCPWriteTimeout,
		conn:         c,
		reader:       bufio.NewReader(c),
	}
}

// NewRawTCPLayer wraps an already-open net.Conn as a transport.Layer that
// uses the same 4-byte length-prefix framing as HTTPConnect but skips the
// HTTP CONNECT handshake.  Primarily used in tests to speak NABU framing
// directly over an existing connection (e.g. a TLS connection dialled by
// the test itself).
func NewRawTCPLayer(c net.Conn) *HTTPConnect { return WrapConn(c) }

// SetReadTimeout implements transport.ReadTimeoutSetter.
func (h *HTTPConnect) SetReadTimeout(d time.Duration) { h.ReadTimeout = d }

// SetSessionKey implements transport.SessionKeySetter.
func (h *HTTPConnect) SetSessionKey(key []byte) { h.SessionKey = key }

// Connect dials the underlying TCP connection, optionally upgrades it to TLS
// (when RelayTLSConfig is set), and then (when ProxyAddr is set) issues an
// HTTP/1.1 CONNECT handshake.
func (h *HTTPConnect) Connect() error {
	dialTarget := h.RelayAddr
	if h.ProxyAddr != "" {
		dialTarget = h.ProxyAddr
	}
	dialer := &net.Dialer{Timeout: h.DialTimeout}
	tcpConn, err := dialer.Dial("tcp", dialTarget)
	if err != nil {
		return fmt.Errorf("tcp dial %s failed: %w", dialTarget, err)
	}

	var conn net.Conn = tcpConn
	if h.UTLSEnabled && h.RelayTLSConfig != nil {
		// uTLS path: close the plain TCP conn first, UTLSDial opens its own.
		_ = tcpConn.Close()
		fingerprint := h.UTLSFingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		helloID, err := ParseUTLSFingerprint(fingerprint)
		if err != nil {
			return fmt.Errorf("utls fingerprint: %w", err)
		}
		utlsCfg := &utls.Config{
			InsecureSkipVerify: h.RelayTLSConfig.InsecureSkipVerify, //nolint:gosec // caller opt-in
			ServerName:         h.RelayTLSConfig.ServerName,
		}
		conn, err = UTLSDial(dialTarget, utlsCfg, helloID, h.DialTimeout)
		if err != nil {
			return err
		}
	} else if h.RelayTLSConfig != nil {
		// Standard TLS path.
		host, _, err := net.SplitHostPort(h.RelayAddr)
		if err != nil {
			_ = tcpConn.Close()
			return fmt.Errorf("parse relay addr for TLS SNI: %w", err)
		}
		tlsCfg := h.RelayTLSConfig.Clone()
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}
		tlsConn := tls.Client(tcpConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			_ = tcpConn.Close()
			return fmt.Errorf("tls handshake failed: %w", err)
		}
		conn = tlsConn
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
