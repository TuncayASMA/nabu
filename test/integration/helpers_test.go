package integration

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/TuncayASMA/nabu/pkg/relay"
)

func TestMain(m *testing.M) {
	// Verify no goroutine leaks across the whole integration test binary.
	// We ignore the goroutines that goleak considers benign background workers.
	goleak.VerifyTestMain(m)
	// VerifyTestMain calls os.Exit internally — code below is unreachable,
	// but we keep it to satisfy Go's "main must return" linting rules.
	os.Exit(m.Run())
}

// getFreeUDPAddr picks an OS-assigned free UDP port on loopback.
// Note: there is a small TOCTOU window between the Close() and when the caller
// binds the port, but in practice this is negligible for sequential tests.
func getFreeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet failed: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// startTCPEchoServer starts a TCP server that echoes all data back to the sender.
// It returns the server address and a cleanup function.
func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Log("warning: echo server did not stop within timeout")
		}
	}

	return ln.Addr().String(), cleanup
}

// startRelayServer starts a UDPServer and registers a t.Cleanup that cancels the
// context AND waits for the server goroutine to exit before the test function
// returns. This prevents relay goroutines from one test from interfering with the
// next test's port allocation or packet processing.
func startRelayServer(t *testing.T) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	addr := getFreeUDPAddr(t)
	s, err := relay.NewUDPServer(addr, nil)
	if err != nil {
		t.Fatalf("new relay server failed: %v", err)
	}
	s.AllowPrivateTargets = true
	return startConfiguredRelay(t, addr, s)
}

// startConfiguredRelay starts a pre-configured UDPServer and registers cleanup.
// Callers that need to set fields on the server before starting should create the
// server themselves, configure it, then call this function.
func startConfiguredRelay(t *testing.T, addr string, s *relay.UDPServer) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(ctx) }()

	// Wait for the relay's UDP socket to be fully operational.
	time.Sleep(200 * time.Millisecond)

	// Register cleanup: cancel the relay context and wait for full shutdown.
	// This ensures the UDP port is released before the next test runs.
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(3 * time.Second):
			t.Log("warning: relay did not stop within cleanup timeout")
		}
	})

	return addr, cancel, errCh
}
