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
	"github.com/TuncayASMA/nabu/pkg/socks5"
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

// dialSOCKS5 connects to a SOCKS5 proxy at proxyAddr and sends a CONNECT
// request for targetAddr (host:port). It returns the established net.Conn
// ready for application-level I/O after the SOCKS5 handshake completes.
// Only IPv4 numeric host addresses are supported.
func dialSOCKS5(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// SOCKS5 greeting: VERSION=5, NAUTH=1, METHOD=NO_AUTH
	if _, err = conn.Write([]byte{socks5.Version5, 1, socks5.NoAuth}); err != nil {
		conn.Close()
		return nil, err
	}
	// Read 2-byte server method selection
	resp := make([]byte, 2)
	if _, err = io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	// Parse host and port from targetAddr
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		conn.Close()
		return nil, net.InvalidAddrError("dialSOCKS5: only IPv4 numeric hosts supported")
	}
	var portNum int
	if _, err = net.LookupPort("tcp", portStr); false {
		_ = err
	}
	for _, c := range portStr {
		portNum = portNum*10 + int(c-'0')
	}

	// SOCKS5 CONNECT request: VER CMD RSV ATYP IP[4] PORT[2]
	req := []byte{
		socks5.Version5, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4,
		ip[0], ip[1], ip[2], ip[3],
		byte(portNum >> 8), byte(portNum & 0xff),
	}
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read 10-byte SOCKS5 CONNECT response
	connResp := make([]byte, 10)
	if _, err = io.ReadFull(conn, connResp); err != nil {
		conn.Close()
		return nil, err
	}
	if connResp[1] != 0x00 {
		conn.Close()
		return nil, net.InvalidAddrError("SOCKS5 CONNECT refused")
	}

	return conn, nil
}
