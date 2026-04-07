package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

type UDPServer struct {
	ListenAddr string
	Logger     *slog.Logger
	conn       net.PacketConn
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

func (s *UDPServer) Start(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("udp listen failed: %w", err)
	}
	s.conn = pc
	defer s.conn.Close()

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

		s.Logger.Info("frame received", "remote", addr.String(), "stream", frame.StreamID, "seq", frame.Seq, "payload_bytes", len(frame.Payload))
	}
}
