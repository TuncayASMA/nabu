package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/TuncayASMA/nabu/pkg/crypto"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

const (
	quicFrameLenHeader = 4
	quicMaxFrameSize   = transport.HeaderSize + transport.MaxPayload
	quicDialTimeout    = 5 * time.Second
	quicIOTimeout      = 30 * time.Second

	// quicALPN is the TLS Application-Layer Protocol Negotiation value
	// advertised by both relay and client.  Passively it looks like a generic
	// h3 endpoint; we use a private value to avoid protocol confusion.
	quicALPN = "nabu/1"
)

// QUICServer accepts QUIC connections carrying length-prefixed NABU frames
// over QUIC streams.  Each QUIC stream maps to one NABU logical stream.
//
// From the outside the endpoint is indistinguishable from an HTTP/3 server:
// it speaks QUIC + TLS 1.3 on UDP and, when ProbeDefense is enabled, serves
// a decoy HTTP/0.9 response on unauthenticated connections.
type QUICServer struct {
	ListenAddr          string
	TLSConfig           *tls.Config
	Logger              *slog.Logger
	AllowPrivateTargets bool
	// PSK enables AES-256-GCM frame encryption (same handshake as TCPServer).
	PSK []byte
	// ProbeDefense serves decoy responses to unauthenticated connections and
	// bans repeat probers.
	ProbeDefense *ProbeDefense
	// Stats exposes server-wide traffic counters.
	Stats GlobalStats
}

// NewQUICServer creates a QUICServer. logger may be nil (defaults to stderr).
// tlsConf must include at least one certificate; use crypto.BuildTLSConfig for
// a self-signed cert that looks like a real HTTPS endpoint.
func NewQUICServer(listenAddr string, tlsConf *tls.Config, logger *slog.Logger) (*QUICServer, error) {
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address cannot be empty")
	}
	if tlsConf == nil {
		return nil, fmt.Errorf("TLS config is required for QUIC")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	// Ensure the NABU ALPN is advertised alongside any existing protocols.
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = appendIfMissing(tlsConf.NextProtos, quicALPN, "h3")
	tlsConf.MinVersion = tls.VersionTLS13
	return &QUICServer{
		ListenAddr: listenAddr,
		TLSConfig:  tlsConf,
		Logger:     logger,
	}, nil
}

// Start listens on UDP and dispatches each accepted QUIC connection to a
// goroutine.  It blocks until ctx is cancelled or a fatal listen error occurs.
func (s *QUICServer) Start(ctx context.Context) error {
	ln, err := quic.ListenAddr(s.ListenAddr, s.TLSConfig, &quic.Config{
		MaxIdleTimeout:        90 * time.Second,
		EnableDatagrams:       false,
		MaxIncomingStreams:    256,
		MaxIncomingUniStreams: -1, // disabled
		Allow0RTT:             false,
	})
	if err != nil {
		return fmt.Errorf("quic listen failed: %w", err)
	}
	defer ln.Close()

	s.Logger.Info("QUICServer listening", "addr", s.ListenAddr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.Logger.Warn("quic accept failed", "error", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn manages a single QUIC connection; each QUIC stream is handled in
// its own goroutine.
func (s *QUICServer) handleConn(ctx context.Context, conn *quic.Conn) {
	defer func() { _ = conn.CloseWithError(0, "relay closed") }()

	remote := conn.RemoteAddr()
	s.Logger.Info("quic connection", "remote", remote.String(),
		"alpn", conn.ConnectionState().TLS.NegotiatedProtocol)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil || isQUICApplicationClose(err) {
				return
			}
			s.Logger.Warn("quic stream accept failed", "remote", remote.String(), "error", err)
			return
		}
		go s.handleStream(ctx, conn, stream)
	}
}

// handleStream manages a single QUIC stream as a NABU relay session.
func (s *QUICServer) handleStream(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()

	remote := conn.RemoteAddr()
	reader := bufio.NewReaderSize(stream, 65536)

	// Probe defense: peek at first 4 bytes.
	if s.ProbeDefense != nil {
		_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
		peek, peekErr := reader.Peek(4)
		_ = stream.SetReadDeadline(time.Time{})
		if peekErr != nil || IsHTTPMethodPrefix(peek) {
			s.Logger.Info("quic probe detected, serving decoy", "remote", remote.String())
			// Wrap stream into a net.Conn-like forwarder for HandleProbe.
			s.ProbeDefense.HandleProbe(quicStreamConn{stream, conn}, reader)
			return
		}
	}

	var sessionKey []byte
	replay := NewReplayWindow()

	for {
		if ctx.Err() != nil {
			return
		}

		frame, err := s.readFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.Logger.Warn("quic frame read error", "remote", remote.String(), "error", err)
			}
			return
		}

		// Decrypt non-handshake frames.
		if frame.Flags&transport.FlagHandshake == 0 && len(frame.Payload) > 0 && len(sessionKey) == crypto.AES256KeySize {
			dec, err := crypto.Decrypt(frame.Payload, sessionKey)
			if err != nil {
				s.Logger.Warn("quic decrypt failed", "remote", remote.String(), "error", err)
				return
			}
			frame.Payload = dec
		}

		// Anti-replay.
		if frame.Flags&transport.FlagHandshake == 0 {
			if !replay.Check(frame.Seq) {
				s.Logger.Warn("quic frame dropped: replay", "remote", remote.String(), "seq", frame.Seq)
				continue
			}
		} else {
			replay.Reset()
		}

		s.Stats.FramesIn.Add(1)
		s.Stats.BytesIn.Add(int64(len(frame.Payload)))

		// Require handshake when PSK configured.
		if len(s.PSK) > 0 && len(sessionKey) == 0 && frame.Flags&transport.FlagHandshake == 0 {
			s.Logger.Warn("quic: handshake required", "remote", remote.String())
			if s.ProbeDefense != nil {
				s.ProbeDefense.HandleProbe(quicStreamConn{stream, conn}, reader)
			}
			return
		}

		switch {
		case frame.Flags&transport.FlagHandshake != 0:
			key, err := s.handleHandshake(stream, frame)
			if err != nil {
				s.Logger.Warn("quic handshake failed", "remote", remote.String(), "error", err)
				return
			}
			sessionKey = key

		case frame.Flags&transport.FlagPing != 0:
			pong := transport.Frame{
				Version:  transport.FrameVersion,
				Flags:    transport.FlagPong,
				StreamID: frame.StreamID,
				Ack:      frame.Seq,
			}
			if err := s.writeFrame(stream, pong, sessionKey); err != nil {
				s.Logger.Warn("quic pong failed", "remote", remote.String(), "error", err)
				return
			}

		case frame.Flags&transport.FlagConnect != 0:
			if err := s.handleConnect(ctx, stream, remote, frame, sessionKey); err != nil {
				s.Logger.Warn("quic CONNECT failed", "remote", remote.String(), "stream", frame.StreamID, "error", err)
			}
			// handleConnect runs a blocking pipe loop; when it returns the
			// stream is done.
			return

		default:
			s.Logger.Warn("quic unexpected frame before CONNECT", "remote", remote.String(), "flags", frame.Flags)
			return
		}
	}
}

// handleConnect dials the target, writes ACK, then pipes bidirectionally.
func (s *QUICServer) handleConnect(ctx context.Context, stream *quic.Stream, _ net.Addr, frame transport.Frame, sessionKey []byte) error {
	targetAddr := string(frame.Payload)
	if err := s.validateDest(targetAddr); err != nil {
		return err
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, quicDialTimeout)
	if err != nil {
		return fmt.Errorf("target dial: %w", err)
	}
	defer targetConn.Close()

	if err := s.writeACK(stream, frame.StreamID, frame.Seq, sessionKey); err != nil {
		return err
	}

	// Pipe relay→target and target→relay concurrently.
	errCh := make(chan error, 2)

	// client NABU frames → target TCP.
	go func() {
		reader := bufio.NewReaderSize(stream, 65536)
		replay := NewReplayWindow()
		var nxt uint32
		for {
			f, err := s.readFrame(reader)
			if err != nil {
				errCh <- err
				return
			}
			if f.Flags&transport.FlagFIN != 0 {
				_ = s.writeACK(stream, f.StreamID, f.Seq, sessionKey)
				errCh <- io.EOF
				return
			}
			if f.Flags&transport.FlagData == 0 {
				continue
			}
			if !replay.Check(f.Seq) {
				continue
			}
			// Decrypt.
			payload := f.Payload
			if len(sessionKey) == crypto.AES256KeySize && len(payload) > 0 {
				dec, err := crypto.Decrypt(payload, sessionKey)
				if err != nil {
					errCh <- err
					return
				}
				payload = dec
			}
			_ = targetConn.SetWriteDeadline(time.Now().Add(quicIOTimeout))
			if _, err := targetConn.Write(payload); err != nil {
				errCh <- err
				return
			}
			nxt = f.Seq + 1
			_ = nxt // suppress unused warning
			s.Stats.BytesIn.Add(int64(len(payload)))
		}
	}()

	// target TCP → client NABU DATA frames.
	go func() {
		buf := make([]byte, 1300)
		for {
			_ = targetConn.SetReadDeadline(time.Now().Add(quicIOTimeout))
			n, err := targetConn.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				s.Stats.BytesOut.Add(int64(n))
				df := transport.Frame{
					Version:  transport.FrameVersion,
					Flags:    transport.FlagData,
					StreamID: frame.StreamID,
					Seq:      nextTCPRelaySeq(),
					Payload:  payload,
				}
				if sendErr := s.writeFrame(stream, df, sessionKey); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				// Send FIN to client.
				fin := transport.Frame{
					Version:  transport.FrameVersion,
					Flags:    transport.FlagFIN,
					StreamID: frame.StreamID,
					Seq:      nextTCPRelaySeq(),
				}
				_ = s.writeFrame(stream, fin, sessionKey)
				errCh <- err
				return
			}
		}
	}()

	// Context cancellation.
	go func() {
		<-ctx.Done()
		errCh <- ctx.Err()
	}()

	<-errCh
	return nil
}

// ── PSK handshake ────────────────────────────────────────────────────────────

func (s *QUICServer) handleHandshake(stream *quic.Stream, frame transport.Frame) ([]byte, error) {
	if len(s.PSK) == 0 {
		ack := transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagHandshake | transport.FlagACK,
			StreamID: frame.StreamID,
			Ack:      frame.Seq,
		}
		return nil, s.writeFrame(stream, ack, nil)
	}
	if len(frame.Payload) != crypto.X25519PublicKeySize {
		return nil, fmt.Errorf("bad pubkey length: %d", len(frame.Payload))
	}
	kp, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}
	shared, err := crypto.X25519SharedSecret(kp.Private[:], frame.Payload)
	if err != nil {
		return nil, err
	}
	key, err := crypto.DeriveSessionKeyX25519(s.PSK, shared, frame.Payload, kp.Public[:])
	if err != nil {
		return nil, err
	}
	ack := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagHandshake | transport.FlagACK,
		StreamID: frame.StreamID,
		Ack:      frame.Seq,
		Payload:  kp.Public[:],
	}
	if err := s.writeFrame(stream, ack, nil); err != nil {
		return nil, err
	}
	return key, nil
}

// ── Framing helpers ──────────────────────────────────────────────────────────

func (s *QUICServer) readFrame(r *bufio.Reader) (transport.Frame, error) {
	var hdr [quicFrameLenHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return transport.Frame{}, err
	}
	frameLen := binary.BigEndian.Uint32(hdr[:])
	if frameLen > uint32(quicMaxFrameSize) {
		return transport.Frame{}, fmt.Errorf("quic frame too large: %d bytes", frameLen)
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return transport.Frame{}, err
	}
	return transport.DecodeFrame(buf)
}

func (s *QUICServer) writeFrame(w io.Writer, frame transport.Frame, sessionKey []byte) error {
	s.Stats.FramesOut.Add(1)
	s.Stats.BytesOut.Add(int64(len(frame.Payload)))

	if frame.Flags&transport.FlagHandshake == 0 && len(frame.Payload) > 0 && len(sessionKey) == crypto.AES256KeySize {
		enc, err := crypto.Encrypt(frame.Payload, sessionKey)
		if err != nil {
			return fmt.Errorf("quic encrypt failed: %w", err)
		}
		frame.Payload = enc
	}
	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("quic frame encode: %w", err)
	}
	var hdr [quicFrameLenHeader]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	_, err = w.Write(append(hdr[:], raw...))
	return err
}

func (s *QUICServer) writeACK(w io.Writer, streamID uint16, ackSeq uint32, sessionKey []byte) error {
	return s.writeFrame(w, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagACK,
		StreamID: streamID,
		Ack:      ackSeq,
	}, sessionKey)
}

// validateDest replicates TCPServer's private-target check.
func (s *QUICServer) validateDest(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", address, err)
	}
	if s.AllowPrivateTargets {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7", "169.254.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, net_, _ := net.ParseCIDR(cidr)
		if net_.Contains(ip) {
			return fmt.Errorf("target %s is in private range (blocked)", address)
		}
	}
	return nil
}

// ── quicStreamConn ───────────────────────────────────────────────────────────

// quicStreamConn adapts a *quic.Stream to the net.Conn interface required by
// ProbeDefense.HandleProbe.
type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (q quicStreamConn) Read(b []byte) (int, error)         { return q.stream.Read(b) }
func (q quicStreamConn) Write(b []byte) (int, error)        { return q.stream.Write(b) }
func (q quicStreamConn) Close() error                       { return q.stream.Close() }
func (q quicStreamConn) LocalAddr() net.Addr                { return q.conn.LocalAddr() }
func (q quicStreamConn) RemoteAddr() net.Addr               { return q.conn.RemoteAddr() }
func (q quicStreamConn) SetDeadline(t time.Time) error      { return q.stream.SetDeadline(t) }
func (q quicStreamConn) SetReadDeadline(t time.Time) error  { return q.stream.SetReadDeadline(t) }
func (q quicStreamConn) SetWriteDeadline(t time.Time) error { return q.stream.SetWriteDeadline(t) }

// ── Helpers ──────────────────────────────────────────────────────────────────

func appendIfMissing(slice []string, items ...string) []string {
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

func isQUICApplicationClose(err error) bool {
	if err == nil {
		return false
	}
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr)
}
