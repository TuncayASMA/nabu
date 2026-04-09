// WebSocketLayer implements transport.Layer by tunnelling NABU frames over a
// WebSocket connection.
//
// From the network's perspective:
//   - Client sends HTTP GET with Upgrade: websocket headers (RFC 6455)
//   - Server responds with 101 Switching Protocols
//   - Both sides exchange WebSocket binary frames (opcode 0x02)
//
// This disguises NABU traffic as WebSocket traffic, which is ubiquitous in
// modern web applications and rarely blocked even by aggressive DPI filters.
//
// Optionally, if TLSConfig is set, the TCP connection is first wrapped with
// TLS (producing WSS — WebSocket Secure), which is even more common and
// provides an additional layer of traffic normalisation.
package obfuscation

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// WebSocketLayer implements transport.Layer.
// Zero value is not usable — construct via NewWebSocketLayer.
type WebSocketLayer struct {
	// RelayAddr is the TCP/TLS endpoint of the NABU relay ("host:port").
	RelayAddr string

	// Path is the HTTP request path for the WebSocket upgrade, e.g. "/ws".
	// Defaults to "/" when empty.
	Path string

	// Host overrides the HTTP Host header. When empty it is derived from RelayAddr.
	Host string

	// DialTimeout is the maximum time allowed for the initial TCP dial.
	DialTimeout time.Duration

	// ReadTimeout is the per-frame read deadline after the connection is established.
	ReadTimeout time.Duration

	// WriteTimeout is the per-frame write deadline.
	WriteTimeout time.Duration

	// SessionKey is set by the NABU handshake after connection establishment.
	SessionKey []byte

	// TLSConfig, when non-nil, wraps the TCP connection with TLS before the
	// WebSocket upgrade (WSS).  Set tls.Config.InsecureSkipVerify for
	// self-signed relay certificates in test/dev environments.
	TLSConfig *tls.Config

	// UTLSEnabled, when true, replaces the standard Go TLS dialer with a uTLS
	// dialer that mimics the ClientHello of a real browser.
	// TLSConfig must also be non-nil for uTLS to activate (it provides InsecureSkipVerify).
	UTLSEnabled bool

	// UTLSFingerprint selects the browser fingerprint (case-insensitive).
	// Valid: chrome (default), firefox, safari, edge, golang, random.
	// Ignored when UTLSEnabled is false.
	UTLSFingerprint string

	// rawConn is the underlying TCP (or TLS) connection; kept for deadline ops.
	rawConn net.Conn

	// wsConn is rawConn wrapped with WebSocket framing.
	wsConn net.Conn

	// reader buffers reads from wsConn (each wsConn.Read returns one WS frame payload).
	reader *bufio.Reader
}

var _ transport.Layer = (*WebSocketLayer)(nil)
var _ transport.ReadTimeoutSetter = (*WebSocketLayer)(nil)
var _ transport.SessionKeySetter = (*WebSocketLayer)(nil)

// NewWebSocketLayer returns a WebSocketLayer with sensible defaults.
func NewWebSocketLayer(relayAddr string) (*WebSocketLayer, error) {
	if relayAddr == "" {
		return nil, fmt.Errorf("relay address cannot be empty")
	}
	return &WebSocketLayer{
		RelayAddr:    relayAddr,
		DialTimeout:  DefaultTCPDialTimeout,
		ReadTimeout:  DefaultTCPReadTimeout,
		WriteTimeout: DefaultTCPWriteTimeout,
	}, nil
}

// Connect dials the relay, optionally upgrades to TLS, performs the WebSocket
// Upgrade handshake, and leaves the layer ready for SendFrame / ReceiveFrame.
func (w *WebSocketLayer) Connect() error {
	dialer := net.Dialer{Timeout: w.DialTimeout}
	tcpConn, err := dialer.Dial("tcp", w.RelayAddr)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}

	var conn net.Conn = tcpConn

	// Optional TLS upgrade (WSS).
	if w.UTLSEnabled && w.TLSConfig != nil {
		// Close plain TCP conn; UTLSDial opens its own.
		_ = tcpConn.Close()
		fingerprint := w.UTLSFingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		helloID, err := ParseUTLSFingerprint(fingerprint)
		if err != nil {
			return fmt.Errorf("utls fingerprint: %w", err)
		}
		utlsCfg := &utls.Config{
			InsecureSkipVerify: w.TLSConfig.InsecureSkipVerify, //nolint:gosec // caller opt-in
			ServerName:         w.TLSConfig.ServerName,
		}
		conn, err = UTLSDial(w.RelayAddr, utlsCfg, helloID, w.DialTimeout)
		if err != nil {
			return err
		}
	} else if w.TLSConfig != nil {
		host, _, _ := net.SplitHostPort(w.RelayAddr)
		cfg := w.TLSConfig.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		tlsConn := tls.Client(tcpConn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			_ = tcpConn.Close()
			return fmt.Errorf("websocket tls: %w", err)
		}
		conn = tlsConn
	}

	// Determine HTTP Host header.
	host := w.Host
	if host == "" {
		h, _, _ := net.SplitHostPort(w.RelayAddr)
		host = h
	}
	path := w.Path
	if path == "" {
		path = "/"
	}

	// WebSocket Upgrade handshake (RFC 6455).
	if err := WSClientHandshake(conn, host, path); err != nil {
		_ = conn.Close()
		return fmt.Errorf("websocket upgrade: %w", err)
	}

	w.rawConn = conn
	w.wsConn = WrapWebSocket(conn, true /*isClient=mask outbound*/)
	w.reader = bufio.NewReaderSize(w.wsConn, 65536)
	return nil
}

// ── transport.Layer ──────────────────────────────────────────────────────────

// SendFrame encodes frame with a 4-byte big-endian length prefix and writes it
// as a single WebSocket binary frame.
func (w *WebSocketLayer) SendFrame(frame transport.Frame) error {
	if w.wsConn == nil {
		return fmt.Errorf("not connected")
	}
	_ = w.rawConn.SetWriteDeadline(time.Now().Add(w.WriteTimeout))

	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("ws encode: %w", err)
	}

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))

	// Single Write → single WS binary frame.
	_, err = w.wsConn.Write(append(hdr[:], raw...))
	return err
}

// ReceiveFrame reads a 4-byte length-prefixed NABU frame from the WebSocket
// stream.
func (w *WebSocketLayer) ReceiveFrame() (transport.Frame, error) {
	if w.reader == nil {
		return transport.Frame{}, fmt.Errorf("not connected")
	}

	var hdr [4]byte
	if _, err := w.reader.Read(hdr[:]); err != nil {
		return transport.Frame{}, fmt.Errorf("ws recv hdr: %w", err)
	}
	frameLen := binary.BigEndian.Uint32(hdr[:])
	if frameLen > uint32(transport.HeaderSize+transport.MaxPayload) {
		return transport.Frame{}, fmt.Errorf("ws frame too large: %d bytes", frameLen)
	}

	buf := make([]byte, frameLen)
	if _, err := w.reader.Read(buf); err != nil {
		return transport.Frame{}, fmt.Errorf("ws recv body: %w", err)
	}
	return transport.DecodeFrame(buf)
}

// Close closes the underlying connection.
func (w *WebSocketLayer) Close() error {
	if w.rawConn != nil {
		return w.rawConn.Close()
	}
	return nil
}

// ── transport.ReadTimeoutSetter ──────────────────────────────────────────────

func (w *WebSocketLayer) SetReadTimeout(d time.Duration) {
	w.ReadTimeout = d
	if w.rawConn != nil {
		_ = w.rawConn.SetReadDeadline(time.Now().Add(d))
	}
}

// ── transport.SessionKeySetter ───────────────────────────────────────────────

func (w *WebSocketLayer) SetSessionKey(key []byte) {
	w.SessionKey = key
}
