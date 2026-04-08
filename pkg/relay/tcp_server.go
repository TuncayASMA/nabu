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
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	nabuCrypto "github.com/TuncayASMA/nabu/pkg/crypto"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

const (
	tcpFrameLenHeader    = 4 // bytes for length prefix
	tcpMaxFrameSize      = transport.HeaderSize + transport.MaxPayload
	tcpTargetDialTimeout = 5 * time.Second
	tcpTargetIOTimeout   = 30 * time.Second
)

// TCPServer accepts TCP connections carrying length-prefixed NABU frames.
// It is the relay-side counterpart of the obfuscation.HTTPConnect transport.
// Each connection handles exactly one client; streams are multiplexed per
// the NABU protocol (StreamID field).
type TCPServer struct {
	ListenAddr          string
	Logger              *slog.Logger
	AllowPrivateTargets bool
	// PSK enables AES-256-GCM frame encryption. When non-empty, each connecting
	// client must perform a FlagHandshake exchange before sending data.
	PSK []byte
	// AcceptHTTPConnect, when true, performs an HTTP/1.1 CONNECT handshake on
	// each incoming connection before starting the NABU frame exchange.
	AcceptHTTPConnect bool
	// TLSConfig, when non-nil, wraps every accepted connection with TLS.
	// A passive DPI observer sees only TLS ClientHello (indistinguishable from HTTPS).
	TLSConfig *tls.Config
	// Stats exposes server-wide traffic counters.
	Stats GlobalStats

	streams sync.Map // key=streamStateKey(), value=*StreamState
}

// NewTCPServer creates a TCPServer. logger may be nil (defaults to stderr).
func NewTCPServer(listenAddr string, logger *slog.Logger) (*TCPServer, error) {
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address cannot be empty")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &TCPServer{
		ListenAddr: listenAddr,
		Logger:     logger,
	}, nil
}

// Start listens for TCP connections and dispatches each to a goroutine.
// It blocks until ctx is cancelled or a fatal listen error occurs.
func (s *TCPServer) Start(ctx context.Context) error {
	tcpLn, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("tcp listen failed: %w", err)
	}

	// Optionally wrap with TLS.
	var ln net.Listener
	if s.TLSConfig != nil {
		ln = tls.NewListener(tcpLn, s.TLSConfig)
	} else {
		ln = tcpLn
	}
	defer ln.Close()

	tls_ := s.TLSConfig != nil
	s.Logger.Info("TCPServer listening", "addr", s.ListenAddr, "http_connect", s.AcceptHTTPConnect, "tls", tls_)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			s.Logger.Warn("tcp accept failed", "error", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// handleConn manages a single client TCP connection.
func (s *TCPServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()

	if s.AcceptHTTPConnect {
		if err := s.acceptHTTPConnect(conn); err != nil {
			s.Logger.Warn("HTTP CONNECT accept failed", "remote", remote.String(), "error", err)
			return
		}
	}

	reader := bufio.NewReaderSize(conn, 65536)
	var sessionKey []byte

	for {
		if ctx.Err() != nil {
			return
		}

		frame, err := s.readFrame(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.Logger.Warn("frame read error", "remote", remote.String(), "error", err)
			}
			return
		}

		// Decrypt non-handshake frames when session key is available.
		if frame.Flags&transport.FlagHandshake == 0 && len(frame.Payload) > 0 && len(sessionKey) == nabuCrypto.AES256KeySize {
			dec, err := nabuCrypto.Decrypt(frame.Payload, sessionKey)
			if err != nil {
				s.Logger.Warn("decrypt failed", "remote", remote.String(), "error", err)
				return
			}
			frame.Payload = dec
		}

		s.Stats.FramesIn.Add(1)
		s.Stats.BytesIn.Add(int64(len(frame.Payload)))

		// Require handshake when PSK is configured.
		if len(s.PSK) > 0 && len(sessionKey) == 0 && frame.Flags&transport.FlagHandshake == 0 {
			s.Logger.Warn("frame dropped: handshake required", "remote", remote.String())
			continue
		}

		switch {
		case frame.Flags&transport.FlagHandshake != 0:
			key, err := s.handleHandshake(conn, frame)
			if err != nil {
				s.Logger.Warn("handshake failed", "remote", remote.String(), "error", err)
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
			if err := s.writeFrame(conn, pong, sessionKey); err != nil {
				s.Logger.Warn("pong write failed", "remote", remote.String(), "error", err)
				return
			}

		case frame.Flags&transport.FlagACK != 0:
		// Client ACKs are informational — no action needed on relay side.

		case frame.Flags&transport.FlagConnect != 0:
			key := streamStateKey(frame.StreamID, remote)
			state := s.getOrCreateStreamState(frame.StreamID, remote)
			if err := s.handleConnect(ctx, conn, key, state, frame, sessionKey); err != nil {
				s.Logger.Warn("CONNECT failed", "remote", remote.String(), "stream", frame.StreamID, "error", err)
			}

		case frame.Flags&transport.FlagFIN != 0:
			key := streamStateKey(frame.StreamID, remote)
			if val, ok := s.streams.Load(key); ok {
				st := val.(*StreamState)
				_ = s.writeACK(conn, frame.StreamID, frame.Seq, sessionKey)
				s.closeStreamTCP(key, st)
			}

		case frame.Flags&transport.FlagData != 0:
			state := s.getOrCreateStreamState(frame.StreamID, remote)
			if err := s.handleData(conn, state, frame, sessionKey); err != nil {
				s.Logger.Warn("DATA failed", "remote", remote.String(), "stream", frame.StreamID, "error", err)
			}

		default:
			s.Logger.Warn("unknown frame flags", "remote", remote.String(), "flags", frame.Flags)
		}
	}
}

// ── Framing helpers ──────────────────────────────────────────────────────────

// readFrame reads one length-prefixed NABU frame from reader.
func (s *TCPServer) readFrame(r *bufio.Reader) (transport.Frame, error) {
	var hdr [tcpFrameLenHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return transport.Frame{}, err
	}
	frameLen := binary.BigEndian.Uint32(hdr[:])
	if frameLen > uint32(tcpMaxFrameSize) {
		return transport.Frame{}, fmt.Errorf("frame too large: %d bytes", frameLen)
	}
	buf := make([]byte, frameLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return transport.Frame{}, err
	}
	return transport.DecodeFrame(buf)
}

// writeFrame encodes and writes a length-prefixed NABU frame to conn.
// Encrypts payload (non-handshake, non-empty) when sessionKey is set.
func (s *TCPServer) writeFrame(conn net.Conn, frame transport.Frame, sessionKey []byte) error {
	s.Stats.FramesOut.Add(1)
	s.Stats.BytesOut.Add(int64(len(frame.Payload)))

	if frame.Flags&transport.FlagHandshake == 0 && len(frame.Payload) > 0 && len(sessionKey) == nabuCrypto.AES256KeySize {
		enc, err := nabuCrypto.Encrypt(frame.Payload, sessionKey)
		if err != nil {
			return fmt.Errorf("encrypt failed: %w", err)
		}
		frame.Payload = enc
	}

	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("frame encode failed: %w", err)
	}

	var hdr [tcpFrameLenHeader]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))

	if _, err := conn.Write(append(hdr[:], raw...)); err != nil {
		return fmt.Errorf("frame write failed: %w", err)
	}
	return nil
}

// writeACK sends a plain ACK frame (no payload) without encryption.
func (s *TCPServer) writeACK(conn net.Conn, streamID uint16, ackSeq uint32, sessionKey []byte) error {
	return s.writeFrame(conn, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagACK,
		StreamID: streamID,
		Ack:      ackSeq,
	}, sessionKey)
}

// ── HTTP CONNECT handshake ───────────────────────────────────────────────────

// acceptHTTPConnect reads an HTTP CONNECT request and sends a 200 response.
// After this call the connection carries raw NABU frames.
func (s *TCPServer) acceptHTTPConnect(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("read CONNECT request: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if req.Method != http.MethodConnect {
		return fmt.Errorf("expected CONNECT, got %s", req.Method)
	}
	_, err = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	return err
}

// ── PSK handshake ────────────────────────────────────────────────────────────

// handleHandshake performs X25519 DH + HKDF and returns the session key.
// Sends plaintext handshake ACK carrying relay pubkey.
func (s *TCPServer) handleHandshake(conn net.Conn, frame transport.Frame) ([]byte, error) {
	if len(s.PSK) == 0 {
		// No PSK: send ACK with no key payload.
		ack := transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagHandshake | transport.FlagACK,
			StreamID: frame.StreamID,
			Ack:      frame.Seq,
		}
		return nil, s.writeFrame(conn, ack, nil)
	}

	if len(frame.Payload) != nabuCrypto.X25519PublicKeySize {
		return nil, fmt.Errorf("bad client pubkey length: %d", len(frame.Payload))
	}
	clientPub := frame.Payload

	kp, err := nabuCrypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("relay keygen: %w", err)
	}
	shared, err := nabuCrypto.X25519SharedSecret(kp.Private[:], clientPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 shared secret: %w", err)
	}
	key, err := nabuCrypto.DeriveSessionKeyX25519(s.PSK, shared, clientPub, kp.Public[:])
	if err != nil {
		return nil, fmt.Errorf("session key derivation: %w", err)
	}

	ack := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagHandshake | transport.FlagACK,
		StreamID: frame.StreamID,
		Ack:      frame.Seq,
		Payload:  kp.Public[:],
	}
	if err := s.writeFrame(conn, ack, nil); err != nil {
		return nil, err
	}
	return key, nil
}

// ── Stream state helpers ─────────────────────────────────────────────────────

func (s *TCPServer) getOrCreateStreamState(streamID uint16, addr net.Addr) *StreamState {
	key := streamStateKey(streamID, addr)
	if val, ok := s.streams.Load(key); ok {
		return val.(*StreamState)
	}
	st := &StreamState{
		StreamID:      streamID,
		RemoteAddr:    addr,
		LastAckTime:   time.Now(),
		MaxRetries:    3,
		RetryInterval: 300 * time.Millisecond,
		reorderBuf:    make(map[uint32][]byte),
		maxBufFrames:  64,
	}
	s.streams.Store(key, st)
	return st
}

func (s *TCPServer) closeStreamTCP(key string, state *StreamState) {
	s.streams.Delete(key)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.TargetConn != nil {
		_ = state.TargetConn.Close()
		state.TargetConn = nil
	}
}

// validateDest reuses UDPServer's private-target check indirectly.
// We replicate the same check here rather than exporting it from udp_server.go.
func (s *TCPServer) validateDest(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", address, err)
	}
	if s.AllowPrivateTargets {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Domain name — allow (DNS resolves later)
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

// ── Frame handlers ───────────────────────────────────────────────────────────

var tcpRelaySeq uint32

func nextTCPRelaySeq() uint32 {
	return atomic.AddUint32(&tcpRelaySeq, 1)
}

func (s *TCPServer) handleConnect(ctx context.Context, conn net.Conn, key string, state *StreamState, frame transport.Frame, sessionKey []byte) error {
	targetAddr := string(frame.Payload)
	if err := s.validateDest(targetAddr); err != nil {
		return err
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, tcpTargetDialTimeout)
	if err != nil {
		return fmt.Errorf("target dial: %w", err)
	}

	state.mu.Lock()
	state.TargetConn = targetConn
	state.NextExpectedSeq = frame.Seq + 1
	state.mu.Unlock()

	if err := s.writeACK(conn, frame.StreamID, frame.Seq, sessionKey); err != nil {
		s.closeStreamTCP(key, state)
		return err
	}

	go s.pipeTargetToClient(ctx, conn, key, state, targetConn, sessionKey)
	return nil
}

func (s *TCPServer) handleData(conn net.Conn, state *StreamState, frame transport.Frame, sessionKey []byte) error {
	state.mu.Lock()
	nxt := state.NextExpectedSeq
	targetConn := state.TargetConn

	if targetConn == nil {
		state.mu.Unlock()
		return fmt.Errorf("stream %d: no target connection", frame.StreamID)
	}

	// Duplicate: already delivered.
	if nxt > 0 && frame.Seq < nxt {
		lastDelivered := nxt - 1
		state.mu.Unlock()
		return s.writeACK(conn, frame.StreamID, lastDelivered, sessionKey)
	}

	// Out-of-order: buffer.
	if frame.Seq > nxt {
		if len(state.reorderBuf) >= state.maxBufFrames {
			state.mu.Unlock()
			return nil // drop; client retransmits
		}
		state.reorderBuf[frame.Seq] = append([]byte(nil), frame.Payload...)
		state.mu.Unlock()
		if nxt > 0 {
			return s.writeACK(conn, frame.StreamID, nxt-1, sessionKey)
		}
		return nil
	}

	// In-order: deliver + drain buffer.
	state.NextExpectedSeq = nxt + 1
	toDeliver := [][]byte{append([]byte(nil), frame.Payload...)}
	for {
		next := state.NextExpectedSeq
		if buf, ok := state.reorderBuf[next]; ok {
			toDeliver = append(toDeliver, buf)
			delete(state.reorderBuf, next)
			state.NextExpectedSeq++
		} else {
			break
		}
	}
	deliveredSeq := state.NextExpectedSeq - 1
	state.LastAckTime = time.Now()
	state.mu.Unlock()

	for _, payload := range toDeliver {
		_ = targetConn.SetWriteDeadline(time.Now().Add(tcpTargetIOTimeout))
		if _, err := targetConn.Write(payload); err != nil {
			return fmt.Errorf("target write: %w", err)
		}
		state.BytesIn.Add(int64(len(payload)))
	}
	return s.writeACK(conn, frame.StreamID, deliveredSeq, sessionKey)
}

// pipeTargetToClient reads from the target TCP connection and sends DATA frames
// to the client over the shared conn. It exits when ctx is cancelled.
func (s *TCPServer) pipeTargetToClient(ctx context.Context, conn net.Conn, key string, state *StreamState, targetConn net.Conn, sessionKey []byte) {
	// Close targetConn when ctx is cancelled so the Read below unblocks.
	go func() {
		<-ctx.Done()
		_ = targetConn.Close()
	}()
	buf := make([]byte, 1300)
	for {
		_ = targetConn.SetReadDeadline(time.Now().Add(tcpTargetIOTimeout))
		n, err := targetConn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			state.BytesOut.Add(int64(n))
			dataFrame := transport.Frame{
				Version:  transport.FrameVersion,
				Flags:    transport.FlagData,
				StreamID: state.StreamID,
				Seq:      nextTCPRelaySeq(),
				Payload:  payload,
			}
			if sendErr := s.writeFrame(conn, dataFrame, sessionKey); sendErr != nil {
				s.Logger.Warn("relay data send failed", "stream", state.StreamID, "error", sendErr)
				break
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.Logger.Warn("target read failed", "stream", state.StreamID, "error", err)
			}
			finFrame := transport.Frame{
				Version:  transport.FrameVersion,
				Flags:    transport.FlagFIN,
				StreamID: state.StreamID,
				Seq:      nextTCPRelaySeq(),
			}
			_ = s.writeFrame(conn, finFrame, sessionKey)
			break
		}
	}
	s.closeStreamTCP(key, state)
}
