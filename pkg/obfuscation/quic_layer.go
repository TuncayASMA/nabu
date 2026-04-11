package obfuscation

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

const (
	// quicLayerALPN must match QUICServer.quicALPN.
	quicLayerALPN = "nabu/1"

	quicLayerDialTimeout  = 10 * time.Second
	quicLayerWriteTimeout = 5 * time.Second
	quicLayerReadTimeout  = 5 * time.Second
	quicLayerFrameMaxSize = transport.HeaderSize + transport.MaxPayload
)

// QUICLayer implements transport.Layer by tunnelling NABU frames over a QUIC
// stream.  From the network perspective the connection looks like an HTTP/3
// client: QUIC/UDP + TLS 1.3 + ALPN "h3" (and "nabu/1").
//
// Each Connect call opens a new bidirectional QUIC stream on a shared *Conn
// (connection reuse).  First use dials the relay; subsequent uses multiplex
// over the existing QUIC connection, which is one of the key DPI-evasion
// benefits: multiple logical sessions share one QUIC handshake.
type QUICLayer struct {
	RelayAddr    string
	TLSConfig    *tls.Config
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	SessionKey   []byte

	conn *quic.Conn
}

// NewQUICLayer returns a QUICLayer configured to connect to relayAddr.
// tlsConf may be nil (uses system root CAs; set InsecureSkipVerify for
// self-signed relay certs).
func NewQUICLayer(relayAddr string, tlsConf *tls.Config) *QUICLayer {
	if tlsConf == nil {
		tlsConf = &tls.Config{} //nolint:gosec // caller responsibility
	}
	c := tlsConf.Clone()
	c.NextProtos = appendIfMissingObs(c.NextProtos, quicLayerALPN, "h3")
	c.MinVersion = tls.VersionTLS13
	return &QUICLayer{
		RelayAddr:    relayAddr,
		TLSConfig:    c,
		DialTimeout:  quicLayerDialTimeout,
		ReadTimeout:  quicLayerReadTimeout,
		WriteTimeout: quicLayerWriteTimeout,
	}
}

// Connect dials the relay (or reuses an existing connection) and returns a
// net.Conn that reads/writes length-prefixed NABU frames over a QUIC stream.
func (q *QUICLayer) Connect() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), q.DialTimeout)
	defer cancel()

	conn, err := q.getOrDialConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic connect: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// Stale conn — reset and retry once.
		q.conn = nil
		conn2, err2 := q.getOrDialConn(ctx)
		if err2 != nil {
			return nil, fmt.Errorf("quic reconnect: %w", err2)
		}
		stream, err = conn2.OpenStreamSync(ctx)
		if err != nil {
			return nil, fmt.Errorf("quic open stream: %w", err)
		}
		conn = conn2
	}

	return &quicStreamNetConn{
		stream:       stream,
		quicConn:     conn,
		readTimeout:  q.ReadTimeout,
		writeTimeout: q.WriteTimeout,
	}, nil
}

// Close closes the underlying QUIC connection (satisfies transport.Layer).
func (q *QUICLayer) Close() error {
	if q.conn != nil {
		err := q.conn.CloseWithError(0, "layer closed")
		q.conn = nil
		return err
	}
	return nil
}

// SendFrame writes a length-prefixed NABU frame to conn (satisfies transport.Layer).
func (q *QUICLayer) SendFrame(f transport.Frame) error {
	if q.conn == nil {
		return fmt.Errorf("quic: not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), q.WriteTimeout)
	defer cancel()
	stream, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("quic open stream for send: %w", err)
	}
	defer stream.Close()
	_ = stream.SetWriteDeadline(time.Now().Add(q.WriteTimeout))
	return quicWriteFrame(stream, f, q.SessionKey)
}

// ReceiveFrame reads a length-prefixed NABU frame from the connection
// (satisfies transport.Layer). NOTE: QUICLayer is primarily used through
// Connect()+net.Conn; direct ReceiveFrame is for compatibility.
func (q *QUICLayer) ReceiveFrame() (transport.Frame, error) {
	if q.conn == nil {
		return transport.Frame{}, fmt.Errorf("quic: not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), q.ReadTimeout)
	defer cancel()
	stream, err := q.conn.AcceptStream(ctx)
	if err != nil {
		return transport.Frame{}, fmt.Errorf("quic accept stream: %w", err)
	}
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(q.ReadTimeout))
	return quicReadFrame(bufio.NewReader(stream))
}

// ── Framing helpers ──────────────────────────────────────────────────────────

func quicWriteFrame(w io.Writer, frame transport.Frame, _ []byte) error {
	// Payload encryption is handled by the relay/crypto layer above; QUICLayer
	// writes the frame unmodified (the session key only matters to the relay).
	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("quic frame encode: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	_, err = w.Write(append(hdr[:], raw...))
	return err
}

func quicReadFrame(r *bufio.Reader) (transport.Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return transport.Frame{}, err
	}
	sz := binary.BigEndian.Uint32(hdr[:])
	if sz > uint32(quicLayerFrameMaxSize) {
		return transport.Frame{}, fmt.Errorf("quic frame too large: %d", sz)
	}
	buf := make([]byte, sz)
	if _, err := io.ReadFull(r, buf); err != nil {
		return transport.Frame{}, err
	}
	return transport.DecodeFrame(buf)
}

// ── Connection management ────────────────────────────────────────────────────

func (q *QUICLayer) getOrDialConn(ctx context.Context) (*quic.Conn, error) {
	if q.conn != nil {
		// Check conn is still alive.
		select {
		case <-q.conn.Context().Done():
			q.conn = nil
		default:
			return q.conn, nil
		}
	}
	conn, err := quic.DialAddr(ctx, q.RelayAddr, q.TLSConfig, &quic.Config{
		MaxIdleTimeout:  90 * time.Second,
		EnableDatagrams: false,
		Allow0RTT:       false,
	})
	if err != nil {
		return nil, err
	}
	q.conn = conn
	return conn, nil
}

// ── quicStreamNetConn ────────────────────────────────────────────────────────

// quicStreamNetConn adapts a *quic.Stream to net.Conn for use by transport
// layers that expect a net.Conn.
type quicStreamNetConn struct {
	stream       *quic.Stream
	quicConn     *quic.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c *quicStreamNetConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *quicStreamNetConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *quicStreamNetConn) Close() error                { return c.stream.Close() }
func (c *quicStreamNetConn) LocalAddr() net.Addr         { return c.quicConn.LocalAddr() }
func (c *quicStreamNetConn) RemoteAddr() net.Addr        { return c.quicConn.RemoteAddr() }
func (c *quicStreamNetConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}
func (c *quicStreamNetConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}
func (c *quicStreamNetConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// ── Internal helper ──────────────────────────────────────────────────────────

// appendIfMissingObs is the same as relay.appendIfMissing but lives in the
// obfuscation package to avoid a cross-package dependency.
func appendIfMissingObs(slice []string, items ...string) []string {
	for _, item := range items {
		found := false
		for _, s := range slice {
			if s == item {
				found = true
				break
			}
		}
		if !found {
			slice = append(slice, item)
		}
	}
	return slice
}
