package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// StreamState tracks per-stream relay state for timeout and retransmit policies.
type StreamState struct {
	StreamID      uint16
	RemoteAddr    net.Addr
	LastSeq       uint32
	LastAckTime   time.Time
	RetryCount    int
	MaxRetries    int
	RetryInterval time.Duration
}

type UDPServer struct {
	ListenAddr string
	Logger     *slog.Logger
	conn       net.PacketConn
	streams    sync.Map // key: streamStateKey(streamID, remoteAddr), value: *StreamState
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
	}
	s.streams.Store(key, state)
	return state
}

// cleanupExpiredStreams removes streams that haven't been active for the timeout period.
func (s *UDPServer) cleanupExpiredStreams(timeout time.Duration) {
	now := time.Now()
	s.streams.Range(func(key, value interface{}) bool {
		state := value.(*StreamState)
		if now.Sub(state.LastAckTime) > timeout {
			s.Logger.Debug("cleaning up expired stream", "stream", state.StreamID, "remote", state.RemoteAddr)
			s.streams.Delete(key)
		}
		return true
	})
}

func (s *UDPServer) Start(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("udp listen failed: %w", err)
	}
	s.conn = pc
	defer s.conn.Close()

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

		// Track stream state on incoming frame.
		state := s.getOrCreateStreamState(frame.StreamID, addr)
		state.LastSeq = frame.Seq
		state.LastAckTime = time.Now()

		s.Logger.Info("frame received", "remote", addr.String(), "stream", frame.StreamID, "seq", frame.Seq, "payload_bytes", len(frame.Payload))

		// Send ACK frame (future: implement retransmit logic here based on state.RetryCount).
		ackRaw, err := transport.EncodeFrame(transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagACK,
			StreamID: frame.StreamID,
			Seq:      0,
			Ack:      frame.Seq,
		})
		if err != nil {
			s.Logger.Warn("ack frame encode failed", "error", err)
			continue
		}
		if _, err := s.conn.WriteTo(ackRaw, addr); err != nil {
			s.Logger.Warn("ack write failed", "remote", addr.String(), "error", err)
		}
	}
}
