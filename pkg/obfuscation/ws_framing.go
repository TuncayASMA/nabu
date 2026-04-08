// Package obfuscation — WebSocket framing primitives.
//
// This file provides a net.Conn adapter (wsConn) that transparently wraps any
// TCP/TLS connection with WebSocket binary-frame encoding, plus the client-
// and server-side HTTP Upgrade handshake helpers.
//
// Wire layout (one NABU message):
//
//	┌───────────────────────────────────────────────────────────┐
//	│  WebSocket binary frame  (FIN=1, opcode=0x02)             │
//	│  ┌────────────────────────────────────────────────────┐   │
//	│  │  4-byte big-endian length  │  NABU frame bytes     │   │
//	│  └────────────────────────────────────────────────────┘   │
//	└───────────────────────────────────────────────────────────┘
//
// The 4-byte length prefix is kept so the enclosing TCPServer can share the
// same readFrame / writeFrame helpers regardless of whether the connection
// was upgraded to WebSocket or plain HTTP CONNECT.
package obfuscation

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by RFC 6455 §4 WebSocket handshake
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	wsGUID     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsFlagFIN  = byte(0x80) // Final fragment bit (always 1 for us — no fragmentation)
	wsFlagMask = byte(0x80) // Masking bit in second header byte
)

// wsConn wraps a net.Conn with transparent WebSocket binary-frame encoding.
// Every Write call sends all bytes as a single binary frame.
// Read returns bytes from the current WS frame payload; excess bytes are
// buffered and returned on subsequent Read calls.
//
// isClient must be true on the connecting side: RFC 6455 §5.1 requires all
// client-to-server frames to carry a masking key.
type wsConn struct {
	conn     net.Conn
	buf      []byte // unread payload bytes from the most-recent WS frame
	isClient bool
}

// WrapWebSocket wraps conn with WebSocket binary-frame transparent encoding.
// Set isClient=true on the connecting side (masks outbound frames).
func WrapWebSocket(conn net.Conn, isClient bool) net.Conn {
	return &wsConn{conn: conn, isClient: isClient}
}

func (w *wsConn) Read(p []byte) (int, error) {
	// Return buffered bytes from the previous frame first.
	if len(w.buf) > 0 {
		n := copy(p, w.buf)
		w.buf = w.buf[n:]
		return n, nil
	}
	payload, err := wsReadFrame(w.conn)
	if err != nil {
		return 0, err
	}
	n := copy(p, payload)
	if n < len(payload) {
		w.buf = make([]byte, len(payload)-n)
		copy(w.buf, payload[n:])
	}
	return n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	if err := wsWriteFrame(w.conn, p, w.isClient); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error                       { return w.conn.Close() }
func (w *wsConn) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error      { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

// ── Frame encode / decode ────────────────────────────────────────────────────

// wsReadFrame reads one WebSocket frame from r and returns its unmasked payload.
// Only binary (0x02) and continuation (0x00) frames are processed; other
// opcodes (ping/pong/close) are silently consumed and the method recurses to
// read the next data frame.
func wsReadFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}

	masked := hdr[1]&wsFlagMask != 0
	payLen := uint64(hdr[1] & 0x7F)

	switch payLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, fmt.Errorf("ws ext16: %w", err)
		}
		payLen = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, fmt.Errorf("ws ext64: %w", err)
		}
		payLen = binary.BigEndian.Uint64(ext)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, fmt.Errorf("ws mask key: %w", err)
		}
	}

	payload := make([]byte, payLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("ws payload: %w", err)
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

// wsWriteFrame encodes payload as a single WebSocket binary frame and writes to w.
// When mask is true a cryptographically random 4-byte masking key is applied
// (required for client→server frames per RFC 6455 §5.3).
func wsWriteFrame(w io.Writer, payload []byte, mask bool) error {
	n := len(payload)

	// Byte 0: FIN=1, RSV=0, opcode=0x02 (binary)
	b0 := wsFlagFIN | byte(0x02)

	// Byte 1 (and optional extended length): mask bit + payload length.
	var lenBuf [9]byte
	var lenLen int
	switch {
	case n <= 125:
		lenBuf[0] = byte(n)
		lenLen = 1
	case n <= 0xFFFF:
		lenBuf[0] = 126
		binary.BigEndian.PutUint16(lenBuf[1:], uint16(n))
		lenLen = 3
	default:
		lenBuf[0] = 127
		binary.BigEndian.PutUint64(lenBuf[1:], uint64(n))
		lenLen = 9
	}

	var mkBuf [4]byte
	maskLen := 0
	if mask {
		lenBuf[0] |= wsFlagMask
		if _, err := rand.Read(mkBuf[:]); err != nil {
			return fmt.Errorf("ws mask key gen: %w", err)
		}
		maskLen = 4
	}

	frame := make([]byte, 1+lenLen+maskLen+n)
	pos := 0
	frame[pos] = b0
	pos++
	copy(frame[pos:], lenBuf[:lenLen])
	pos += lenLen
	if mask {
		copy(frame[pos:], mkBuf[:])
		pos += 4
	}
	copy(frame[pos:], payload)
	if mask {
		for i := 0; i < n; i++ {
			frame[pos+i] ^= mkBuf[i%4]
		}
	}

	_, err := w.Write(frame)
	return err
}

// ── Handshake helpers ────────────────────────────────────────────────────────

// wsComputeAccept returns the Sec-WebSocket-Accept header value for the given key.
func wsComputeAccept(key string) string {
	h := sha1.New() //nolint:gosec // SHA-1 mandated by RFC 6455 §4.2.2
	h.Write([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsReadLine reads from r one byte at a time until CRLF and returns the line
// content (without the \r\n).  Using single-byte reads avoids any look-ahead
// buffering that could silently consume WS frame bytes arriving immediately
// after the HTTP headers.
func wsReadLine(r io.Reader) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		if _, err := r.Read(b); err != nil {
			return "", err
		}
		if b[0] == '\r' {
			if _, err := r.Read(b); err != nil {
				return "", err
			}
			if b[0] != '\n' {
				return "", fmt.Errorf("ws: expected \\n after \\r")
			}
			return string(line), nil
		}
		line = append(line, b[0])
	}
}

// wsReadHeaders reads HTTP headers from r until the blank line terminator.
// Returns a lowercase-keyed map.
func wsReadHeaders(r io.Reader) (map[string]string, error) {
	h := make(map[string]string)
	for {
		line, err := wsReadLine(r)
		if err != nil {
			return nil, err
		}
		if line == "" {
			return h, nil
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			v := strings.TrimSpace(line[idx+1:])
			h[k] = v
		}
	}
}

// WSClientHandshake performs the RFC 6455 client-side HTTP Upgrade handshake.
// On success conn is positioned immediately after the blank line of the 101
// response, ready for WebSocket frame exchange.
func WSClientHandshake(conn net.Conn, host, path string) error {
	if path == "" {
		path = "/"
	}

	rawKey := make([]byte, 16)
	if _, err := rand.Read(rawKey); err != nil {
		return fmt.Errorf("ws key gen: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(rawKey)
	expectedAccept := wsComputeAccept(key)

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("ws upgrade send: %w", err)
	}

	statusLine, err := wsReadLine(conn)
	if err != nil {
		return fmt.Errorf("ws status read: %w", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") {
		return fmt.Errorf("ws upgrade rejected: %q", statusLine)
	}

	headers, err := wsReadHeaders(conn)
	if err != nil {
		return fmt.Errorf("ws header parse: %w", err)
	}

	if headers["sec-websocket-accept"] != expectedAccept {
		return fmt.Errorf("ws bad accept: got %q want %q",
			headers["sec-websocket-accept"], expectedAccept)
	}
	return nil
}

// WSServerHandshake performs the RFC 6455 server-side HTTP Upgrade handshake.
// On success conn is positioned immediately after the blank line of the 101
// response, ready for WebSocket frame exchange.
func WSServerHandshake(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	reqLine, err := wsReadLine(conn)
	if err != nil {
		return fmt.Errorf("ws server req: %w", err)
	}
	if !strings.HasPrefix(reqLine, "GET ") {
		return fmt.Errorf("ws server: expected GET, got %q", reqLine)
	}

	headers, err := wsReadHeaders(conn)
	if err != nil {
		return fmt.Errorf("ws server headers: %w", err)
	}
	if !strings.EqualFold(headers["upgrade"], "websocket") {
		return fmt.Errorf("ws server: missing Upgrade: websocket header")
	}
	wsKey := headers["sec-websocket-key"]
	if wsKey == "" {
		return fmt.Errorf("ws server: missing Sec-WebSocket-Key header")
	}

	accept := wsComputeAccept(wsKey)
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"

	if _, err := io.WriteString(conn, resp); err != nil {
		return fmt.Errorf("ws server 101 send: %w", err)
	}
	return nil
}
