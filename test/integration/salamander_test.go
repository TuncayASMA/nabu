package integration

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/transport"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
)

// TestSalamanderUDPEcho verifies that Salamander obfuscation wraps UDP frames
// transparently: SOCKS5 client → Salamander-obfuscated relay → TCP echo server
// round-trip must echo back the same payload.
func TestSalamanderUDPEcho(t *testing.T) {
	const testPSKStr = "nabu-salamander-integration-psk"
	salamanderPSK := []byte(testPSKStr)

	relayAddr := getFreeUDPAddr(t)
	relayServer, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new udp server: %v", err)
	}
	relayServer.AllowPrivateTargets = true
	relayServer.SalamanderPSK = salamanderPSK

	relayAddr, _, _ = startConfiguredRelay(t, relayAddr, relayServer)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	// Allocate a free TCP port for the SOCKS5 server.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	socksAddr := socksLn.Addr().String()
	_ = socksLn.Close()

	srv := socks5.NewServer(socksAddr)
	srv.RequestTimeout = 8 * time.Second
	srv.OnConnect = tunnel.NewRelayHandlerUDPSalamander(relayAddr, nil, salamanderPSK)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServeContext(ctx) }()
	time.Sleep(150 * time.Millisecond)

	conn, err := dialSOCKS5(socksAddr, echoAddr)
	if err != nil {
		t.Fatalf("dialSOCKS5: %v", err)
	}
	defer conn.Close()

	payload := []byte("Hello, Salamander!")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
}

// TestSalamanderWrongPSKRejected verifies that a UDPClient with an incorrect
// Salamander PSK cannot communicate with a Salamander-enabled relay.
// The relay performs GCM authentication on every incoming datagram and silently
// drops those that fail — so the client receives nothing back.
func TestSalamanderWrongPSKRejected(t *testing.T) {
	serverPSK := []byte("correct-psk-for-server-side-1234")
	wrongPSK := []byte("incorrect-psk-for-client-12345678")

	relayAddr := getFreeUDPAddr(t)
	relayServer, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new udp server: %v", err)
	}
	relayServer.AllowPrivateTargets = true
	relayServer.SalamanderPSK = serverPSK

	relayAddr, _, _ = startConfiguredRelay(t, relayAddr, relayServer)

	// Create a raw UDP client with the WRONG PSK. Any frame it sends will fail
	// Salamander GCM authentication on the server side and be dropped silently.
	wrongClient, err := transport.NewUDPClient(relayAddr)
	if err != nil {
		t.Fatalf("new udp client: %v", err)
	}
	wrongClient.SalamanderPSK = wrongPSK
	if err := wrongClient.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer wrongClient.Close()

	wrongClient.SetReadTimeout(800 * time.Millisecond)

	if err := wrongClient.SendFrame(transport.Frame{
		Flags:    transport.FlagConnect,
		StreamID: 0xdead,
	}); err != nil {
		t.Fatalf("send frame: %v", err)
	}

	// No response expected: relay drops any packet whose Salamander tag is invalid.
	_, recvErr := wrongClient.ReceiveFrame()
	if recvErr == nil {
		t.Fatal("expected timeout/error with wrong PSK but got a frame back")
	}
	t.Logf("wrong PSK correctly rejected (as expected): %v", recvErr)
}
