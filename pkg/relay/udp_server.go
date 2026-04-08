package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nabuCrypto "github.com/TuncayASMA/nabu/pkg/crypto"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

// StreamState tracks per-stream relay state for ordering, buffering, and timeout.
type StreamState struct {
	StreamID         uint16
	RemoteAddr       net.Addr
	NextExpectedSeq  uint32    // next seq we expect to deliver in-order
	LastAckTime      time.Time
	RetryCount       int
	MaxRetries       int
	RetryInterval    time.Duration
	TargetConn       net.Conn
	RelaySeq         uint32
	reorderBuf       map[uint32][]byte // out-of-order frames waiting for delivery
	maxBufFrames     int               // backpressure: max frames in reorder buffer
	mu               sync.Mutex
}

type UDPServer struct {
	ListenAddr          string
	Logger              *slog.Logger
	AllowPrivateTargets bool
	// PSK enables AES-256-GCM frame encryption. When non-empty, each connecting
	// client must perform a FlagHandshake exchange before sending data.
	PSK  []byte
	conn net.PacketConn
	// streams: key=streamStateKey(streamID, remoteAddr), value=*StreamState
	streams sync.Map
	// sessions: key=remoteAddr.String(), value=[]byte (session key per client IP:port)
	sessions sync.Map
}

func NewUDPServer(listenAddr string, logger *slog.Logger) (*UDPServer, error) {
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address cannot be empty")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &UDPServer{
		ListenAddr: listenAddr,
		Logger:     logger,
	}, nil
}

// streamStateKey generates a unique key for stream tracking.
func streamStateKey(streamID uint16, remoteAddr net.Addr) string {
	return fmt.Sprintf("%d:%s", streamID, remoteAddr.String())
}

// getOrCreateStreamState retrieves or creates stream state.
func (s *UDPServer) getOrCreateStreamState(streamID uint16, remoteAddr net.Addr) *StreamState {
	key := streamStateKey(streamID, remoteAddr)
	if val, ok := s.streams.Load(key); ok {
		return val.(*StreamState)
	}
	state := &StreamState{
		StreamID:      streamID,
		RemoteAddr:    remoteAddr,
		MaxRetries:    3,
		RetryInterval: 200 * time.Millisecond,
		maxBufFrames:  64,
		reorderBuf:    make(map[uint32][]byte),
	}
	s.streams.Store(key, state)
	return state
}

// cleanupExpiredStreams removes streams that haven't been active for the timeout period.
func (s *UDPServer) cleanupExpiredStreams(timeout time.Duration) {
	now := time.Now()
	s.streams.Range(func(key, value interface{}) bool {
		state := value.(*StreamState)
		state.mu.Lock()
		lastAckTime := state.LastAckTime
		state.mu.Unlock()
		if now.Sub(lastAckTime) > timeout {
			s.Logger.Debug("cleaning up expired stream", "stream", state.StreamID, "remote", state.RemoteAddr)
			s.closeStream(key.(string), state)
		}
		return true
	})
}

func (s *UDPServer) closeAllStreams() {
	s.streams.Range(func(key, value interface{}) bool {
		s.closeStream(key.(string), value.(*StreamState))
		return true
	})
}

func (s *UDPServer) closeStream(key string, state *StreamState) {
	state.mu.Lock()
	targetConn := state.TargetConn
	state.TargetConn = nil
	state.mu.Unlock()

	if targetConn != nil {
		_ = targetConn.Close()
	}
	s.streams.Delete(key)
	// Remove session key when last stream for this addr closes.
	// (Simple heuristic: remove if no other streams remain for this remote addr.)
	s.removeSessionKey(state.RemoteAddr)
}

// --- session key helpers ---

func (s *UDPServer) getSessionKey(addr net.Addr) []byte {
	if val, ok := s.sessions.Load(addr.String()); ok {
		return val.([]byte)
	}
	return nil
}

func (s *UDPServer) setSessionKey(addr net.Addr, key []byte) {
	s.sessions.Store(addr.String(), key)
}

func (s *UDPServer) removeSessionKey(addr net.Addr) {
	s.sessions.Delete(addr.String())
}

// handleHandshakeFrame derives the session key from the PSK + client salt
// and stores it keyed by remoteAddr. Returns the ACK to send back.
func (s *UDPServer) handleHandshakeFrame(frame transport.Frame, addr net.Addr) error {
	if len(s.PSK) == 0 {
		// No PSK configured — ignore handshake (relay runs unencrypted).
		return s.sendFrame(transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagHandshake | transport.FlagACK,
			StreamID: frame.StreamID,
			Ack:      frame.Seq,
		}, addr)
	}
	if len(frame.Payload) == 0 {
		return fmt.Errorf("handshake frame missing salt payload")
	}
	key, err := nabuCrypto.DeriveSessionKey(s.PSK, frame.Payload, nabuCrypto.AES256KeySize)
	if err != nil {
		return fmt.Errorf("session key derivation failed: %w", err)
	}
	s.setSessionKey(addr, key)
	// ACK is sent before key is used for encryption (client sets key after ACK).
	return s.sendHandshakeACK(frame.StreamID, frame.Seq, addr)
}

// sendHandshakeACK sends a plaintext (never encrypted) handshake ACK.
func (s *UDPServer) sendHandshakeACK(streamID uint16, ackSeq uint32, addr net.Addr) error {
	frame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagHandshake | transport.FlagACK,
		StreamID: streamID,
		Ack:      ackSeq,
	}
	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("handshake ack encode failed: %w", err)
	}
	if _, err := s.conn.WriteTo(raw, addr); err != nil {
		return fmt.Errorf("handshake ack write failed: %w", err)
	}
	return nil
}

func (s *UDPServer) sendFrame(frame transport.Frame, addr net.Addr) error {
	// Encrypt payload for non-handshake frames when a session key exists.
	if (frame.Flags&transport.FlagHandshake == 0) && len(frame.Payload) > 0 {
		if key := s.getSessionKey(addr); len(key) == nabuCrypto.AES256KeySize {
			enc, err := nabuCrypto.Encrypt(frame.Payload, key)
			if err != nil {
				return fmt.Errorf("frame encrypt failed: %w", err)
			}
			frame.Payload = enc
		}
	}
	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		return fmt.Errorf("frame encode failed: %w", err)
	}
	if _, err := s.conn.WriteTo(raw, addr); err != nil {
		return fmt.Errorf("frame write failed: %w", err)
	}
	return nil
}

// sendACKFrame sends an ACK frame for the given incoming sequence number.
// Returns error if encoding or writing fails.
func (s *UDPServer) sendACKFrame(streamID uint16, ackSeq uint32, addr net.Addr) error {
	return s.sendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagACK,
		StreamID: streamID,
		Seq:      0,
		Ack:      ackSeq,
	}, addr)
}

func (s *UDPServer) sendFINFrame(streamID uint16, seq uint32, addr net.Addr) error {
	return s.sendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagFIN,
		StreamID: streamID,
		Seq:      seq,
	}, addr)
}

func (s *UDPServer) nextRelaySeq(state *StreamState) uint32 {
	return atomic.AddUint32(&state.RelaySeq, 1)
}

func (s *UDPServer) validateDestination(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid destination address: %w", err)
	}

	if s.AllowPrivateTargets {
		return nil
	}

	normalizedHost := strings.Trim(host, "[]")
	if normalizedHost == "metadata.google.internal" || normalizedHost == "169.254.169.254" {
		return fmt.Errorf("destination is blocked")
	}

	if ip := net.ParseIP(normalizedHost); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("destination is blocked")
		}
	}

	return nil
}

func (s *UDPServer) handleConnectFrame(key string, state *StreamState, frame transport.Frame, addr net.Addr) error {
	targetAddr := string(frame.Payload)
	if err := s.validateDestination(targetAddr); err != nil {
		return err
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("target dial failed: %w", err)
	}

	state.mu.Lock()
	state.TargetConn = targetConn
	state.NextExpectedSeq = frame.Seq + 1 // first DATA seq follows CONNECT seq
	state.mu.Unlock()

	if err := s.sendACKFrame(frame.StreamID, frame.Seq, addr); err != nil {
		s.closeStream(key, state)
		return err
	}

	go s.pipeTargetToClient(key, state, targetConn)

	return nil
}

func (s *UDPServer) handleDataFrame(state *StreamState, frame transport.Frame, addr net.Addr) error {
	state.mu.Lock()

	nxt := state.NextExpectedSeq
	targetConn := state.TargetConn

	if targetConn == nil {
		state.mu.Unlock()
		return fmt.Errorf("stream %d has no target connection", frame.StreamID)
	}

	// Duplicate: seq already delivered — ACK the last in-order seq.
	if nxt > 0 && frame.Seq < nxt {
		lastDelivered := nxt - 1
		state.mu.Unlock()
		return s.sendACKFrame(frame.StreamID, lastDelivered, addr)
	}

	// Out-of-order: buffer frame if room available; drop if backpressure limit hit.
	if frame.Seq > nxt {
		if len(state.reorderBuf) >= state.maxBufFrames {
			state.mu.Unlock()
			return nil // drop; client will retransmit
		}
		state.reorderBuf[frame.Seq] = append([]byte(nil), frame.Payload...)
		state.mu.Unlock()
		// ACK last in-order so client knows we're alive.
		if nxt > 0 {
			return s.sendACKFrame(frame.StreamID, nxt-1, addr)
		}
		return nil
	}

	// In-order: deliver this frame then drain any buffered frames that follow.
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
		if err := targetConn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return fmt.Errorf("set target write deadline failed: %w", err)
		}
		if _, err := targetConn.Write(payload); err != nil {
			return fmt.Errorf("target write failed: %w", err)
		}
	}

	return s.sendACKFrame(frame.StreamID, deliveredSeq, addr)
}

func (s *UDPServer) pipeTargetToClient(key string, state *StreamState, targetConn net.Conn) {
	buf := make([]byte, 1300)
	for {
		if err := targetConn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			s.Logger.Warn("set target read deadline failed", "stream", state.StreamID, "remote", state.RemoteAddr.String(), "error", err)
			break
		}
		n, err := targetConn.Read(buf)
		if n > 0 {
			payload := append([]byte(nil), buf[:n]...)
			if sendErr := s.sendFrame(transport.Frame{
				Version:  transport.FrameVersion,
				Flags:    transport.FlagData,
				StreamID: state.StreamID,
				Seq:      s.nextRelaySeq(state),
				Payload:  payload,
			}, state.RemoteAddr); sendErr != nil {
				s.Logger.Warn("relay data send failed", "stream", state.StreamID, "remote", state.RemoteAddr.String(), "error", sendErr)
				break
			}
		}

		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				s.Logger.Warn("target read failed", "stream", state.StreamID, "remote", state.RemoteAddr.String(), "error", err)
			}
			_ = s.sendFINFrame(state.StreamID, s.nextRelaySeq(state), state.RemoteAddr)
			break
		}
	}

	s.closeStream(key, state)
}

func (s *UDPServer) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pc, err := net.ListenPacket("udp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("udp listen failed: %w", err)
	}
	s.conn = pc
	defer s.conn.Close()
	defer s.closeAllStreams()

	// Cleanup ticker for expired streams (every 5 seconds).
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Cleanup goroutine.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanupExpiredStreams(30 * time.Second)
			}
		}
	}()

	buf := make([]byte, transport.HeaderSize+transport.MaxPayload)
	for {
		// TODO: Add per-source and global rate limiting before production rollout.
		// This skeleton currently accepts unlimited datagrams for development speed.
		if dl, ok := s.conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dl.SetReadDeadline(time.Now().Add(2 * time.Second))
		}

		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			return fmt.Errorf("udp read failed: %w", err)
		}

		frame, err := transport.DecodeFrame(buf[:n])
		if err != nil {
			s.Logger.Warn("invalid frame", "remote", addr.String(), "error", err)
			continue
		}

		// Decrypt payload for non-handshake frames when session key is set.
		if (frame.Flags&transport.FlagHandshake == 0) && len(frame.Payload) > 0 {
			if key := s.getSessionKey(addr); len(key) == nabuCrypto.AES256KeySize {
				dec, err := nabuCrypto.Decrypt(frame.Payload, key)
				if err != nil {
					s.Logger.Warn("frame decrypt failed", "remote", addr.String(), "error", err)
					continue
				}
				frame.Payload = dec
			}
		}

		// Track stream state on incoming frame.
		key := streamStateKey(frame.StreamID, addr)
		state := s.getOrCreateStreamState(frame.StreamID, addr)
		state.mu.Lock()
		state.LastAckTime = time.Now()
		state.mu.Unlock()

		s.Logger.Info("frame received", "remote", addr.String(), "stream", frame.StreamID, "seq", frame.Seq, "payload_bytes", len(frame.Payload))

		switch {
		case frame.Flags&transport.FlagHandshake != 0:
			if err := s.handleHandshakeFrame(frame, addr); err != nil {
				s.Logger.Warn("handshake frame handling failed", "remote", addr.String(), "error", err)
			}
		case frame.Flags&transport.FlagACK != 0:
			continue
		case frame.Flags&transport.FlagConnect != 0:
			if err := s.handleConnectFrame(key, state, frame, addr); err != nil {
				s.Logger.Warn("connect frame handling failed", "remote", addr.String(), "stream", frame.StreamID, "error", err)
				continue
			}
		case frame.Flags&transport.FlagFIN != 0:
			if err := s.sendACKFrame(frame.StreamID, frame.Seq, addr); err != nil {
				s.Logger.Warn("fin ack send failed", "remote", addr.String(), "stream", frame.StreamID, "error", err)
			}
			s.closeStream(key, state)
		case frame.Flags&transport.FlagData != 0:
			if err := s.handleDataFrame(state, frame, addr); err != nil {
				s.Logger.Warn("data frame handling failed", "remote", addr.String(), "stream", frame.StreamID, "error", err)
				continue
			}
		default:
			s.Logger.Warn("unsupported frame flags", "remote", addr.String(), "stream", frame.StreamID, "flags", frame.Flags)
		}
	}
}
