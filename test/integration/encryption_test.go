package integration

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
)

// TestEncryptedTunnelEcho verifies that a PSK-encrypted tunnel correctly
// forwards data end-to-end: SOCKS5 client → relay (AES-256-GCM) → TCP echo server.
func TestEncryptedTunnelEcho(t *testing.T) {
	psk := []byte("nabu-integration-test-psk-32byt")

	relayAddr := getFreeUDPAddr(t)

	relayServer, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new udp server: %v", err)
	}
	relayServer.AllowPrivateTargets = true
	relayServer.PSK = psk

	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	relayErrCh := make(chan error, 1)
	go func() {
		relayErrCh <- relayServer.Start(relayCtx)
	}()

	time.Sleep(120 * time.Millisecond)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	server := socks5.NewServer(":0")
	server.RequestTimeout = time.Second
	server.OnConnect = tunnel.NewRelayHandler(relayAddr, psk)

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	socksErrCh := make(chan error, 1)
	go func() {
		socksErrCh <- server.HandleConn(serverConn)
	}()

	// SOCKS5 greeting.
	if _, err := client.Write([]byte{socks5.Version5, 1, socks5.NoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(client, methodResp); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}

	// SOCKS5 CONNECT to echo server.
	host, port, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split host:port: %v", err)
	}
	req := append([]byte{socks5.Version5, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4}, net.ParseIP(host).To4()...)
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		t.Fatalf("lookup port: %v", err)
	}
	req = append(req, byte(portNum>>8), byte(portNum))

	if _, err := client.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}

	// Data round-trip through encrypted relay.
	want := []byte("encrypted nabu tunnel works!")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got=%q want=%q", got, want)
	}

	_ = client.Close()

	select {
	case err := <-socksErrCh:
		if err != nil {
			t.Fatalf("socks handler: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("socks handler did not stop")
	}

	relayCancel()
	select {
	case err := <-relayErrCh:
		if err != nil {
			t.Fatalf("relay server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay server did not stop")
	}
}

// TestEncryptedTunnelMultiPayload verifies that multiple sequential data chunks
// are all correctly encrypted, forwarded, and echoed back.
func TestEncryptedTunnelMultiPayload(t *testing.T) {
	psk := []byte("nabu-integration-test-psk-32byt")

	relayAddr := getFreeUDPAddr(t)

	relayServer, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new udp server: %v", err)
	}
	relayServer.AllowPrivateTargets = true
	relayServer.PSK = psk

	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	go relayServer.Start(relayCtx) //nolint:errcheck

	time.Sleep(120 * time.Millisecond)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	server := socks5.NewServer(":0")
	server.RequestTimeout = time.Second
	server.OnConnect = tunnel.NewRelayHandler(relayAddr, psk)

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	go server.HandleConn(serverConn) //nolint:errcheck

	// Handshake.
	if _, err := client.Write([]byte{socks5.Version5, 1, socks5.NoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}

	host, port, _ := net.SplitHostPort(echoAddr)
	req := append([]byte{socks5.Version5, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4}, net.ParseIP(host).To4()...)
	portNum, _ := net.LookupPort("tcp", port)
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if _, err := io.ReadFull(client, make([]byte, 10)); err != nil {
		t.Fatalf("read CONNECT resp: %v", err)
	}

	// Send three distinct payloads and verify each echo.
	payloads := []string{"first chunk", "second chunk", "third chunk"}
	for _, p := range payloads {
		want := []byte(p)
		if _, err := client.Write(want); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("read echo of %q: %v", p, err)
		}
		if string(got) != p {
			t.Fatalf("multi-payload mismatch: got=%q want=%q", got, p)
		}
	}
}

// TestNoPSKClientRejectedByPSKRelay verifies that a client connecting without a
// PSK cannot forward data through a PSK-protected relay. The relay drops all
// non-handshake frames from unauthenticated sources, so the SOCKS5 handler
// times out on the connect ACK and returns an error.
func TestNoPSKClientRejectedByPSKRelay(t *testing.T) {
	psk := []byte("nabu-integration-test-psk-32byt")

	relayAddr := getFreeUDPAddr(t)

	relayServer, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new udp server: %v", err)
	}
	relayServer.AllowPrivateTargets = true
	relayServer.PSK = psk // relay requires PSK

	relayCtx, relayCancel := context.WithCancel(context.Background())
	defer relayCancel()

	go relayServer.Start(relayCtx) //nolint:errcheck

	time.Sleep(120 * time.Millisecond)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	// Client connects without a PSK (nil).
	server := socks5.NewServer(":0")
	server.RequestTimeout = 3 * time.Second
	server.OnConnect = tunnel.NewRelayHandler(relayAddr, nil) // no PSK!

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	socksErrCh := make(chan error, 1)
	go func() {
		socksErrCh <- server.HandleConn(serverConn)
	}()

	if _, err := client.Write([]byte{socks5.Version5, 1, socks5.NoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}

	host, port, _ := net.SplitHostPort(echoAddr)
	req := append([]byte{socks5.Version5, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4}, net.ParseIP(host).To4()...)
	portNum, _ := net.LookupPort("tcp", port)
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// The socks handler must fail or return an error response (relay drops frame).
	select {
	case err := <-socksErrCh:
		// Any error is acceptable — the relay rejected the connection.
		t.Logf("socks handler returned (expected): %v", err)
	case <-time.After(6 * time.Second):
		t.Fatal("expected socks handler to fail when PSK is missing, but it hung")
	}
}
