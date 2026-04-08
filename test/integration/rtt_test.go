package integration

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/transport"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
)

// TestMeasureRTTOnLiveRelay verifies that MeasureRTT returns a positive,
// loopback-realistic RTT when called against a running relay.
func TestMeasureRTTOnLiveRelay(t *testing.T) {
	relayAddr := getFreeUDPAddr(t)

	srv, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new relay: %v", err)
	}
	srv.AllowPrivateTargets = true

	startConfiguredRelay(t, relayAddr, srv)

	c, err := transport.NewUDPClient(relayAddr)
	if err != nil {
		t.Fatalf("new udp client: %v", err)
	}
	defer c.Close()

	if err := c.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}

	rtt, err := c.MeasureRTT(1, 42)
	if err != nil {
		t.Fatalf("MeasureRTT failed: %v", err)
	}

	if rtt <= 0 {
		t.Fatalf("RTT must be positive, got %v", rtt)
	}
	if rtt > 500*time.Millisecond {
		t.Errorf("RTT unexpectedly high for loopback: %v (want < 500ms)", rtt)
	}
	t.Logf("loopback RTT: %v", rtt)
}

// TestRTTAdaptiveBackoffEndToEnd verifies that the full SOCKS5 → relay tunnel
// operates correctly when RTT-based adaptive timeouts are in effect.
// This is the most important regression guard: if RTT measurement breaks the
// handshake or baseTimeout calculation, data exchange must still succeed.
func TestRTTAdaptiveBackoffEndToEnd(t *testing.T) {
	relayAddr := getFreeUDPAddr(t)

	srv, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new relay: %v", err)
	}
	srv.AllowPrivateTargets = true

	startConfiguredRelay(t, relayAddr, srv)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	// NewRelayHandler internally measures RTT during the CONNECT flow.
	socksServer := socks5.NewServer(":0")
	socksServer.RequestTimeout = 3 * time.Second
	socksServer.OnConnect = tunnel.NewRelayHandler(relayAddr, nil)

	client, serverConn := net.Pipe()
	defer client.Close()
	defer serverConn.Close()

	socksErrCh := make(chan error, 1)
	go func() { socksErrCh <- socksServer.HandleConn(serverConn) }()

	// SOCKS5 greeting.
	if _, err := client.Write([]byte{socks5.Version5, 1, socks5.NoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(client, methodResp); err != nil {
		t.Fatalf("read method resp: %v", err)
	}

	// SOCKS5 CONNECT.
	host, portStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	portNum, _ := net.LookupPort("tcp", portStr)
	req := append([]byte{socks5.Version5, socks5.CmdConnect, 0x00, socks5.AddrTypeIPv4},
		net.ParseIP(host).To4()...)
	req = append(req, byte(portNum>>8), byte(portNum))

	if _, err := client.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("read CONNECT resp: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("CONNECT rejected: rep=%02x", resp[1])
	}

	// Data round-trip — exercises adaptive baseTimeout path.
	want := []byte("rtt-adaptive-backoff-works!")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("write data: %v", err)
	}
	got := make([]byte, len(want))
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
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
			t.Fatalf("socks handler error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("socks handler did not stop")
	}
}

// TestRTTMultipleRoundTrips verifies that calling MeasureRTT several times in
// quick succession gives consistent, positive results (no ghost Pong frames).
func TestRTTMultipleRoundTrips(t *testing.T) {
	relayAddr := getFreeUDPAddr(t)

	srv, err := relay.NewUDPServer(relayAddr, nil)
	if err != nil {
		t.Fatalf("new relay: %v", err)
	}
	srv.AllowPrivateTargets = true

	startConfiguredRelay(t, relayAddr, srv)

	c, err := transport.NewUDPClient(relayAddr)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()

	if err := c.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}

	const iters = 5
	for i := 0; i < iters; i++ {
		rtt, err := c.MeasureRTT(uint16(i+1), uint32(i*100))
		if err != nil {
			t.Errorf("iter %d: MeasureRTT error: %v", i, err)
			continue
		}
		if rtt <= 0 {
			t.Errorf("iter %d: RTT must be positive, got %v", i, rtt)
		}
		t.Logf("iter %d: RTT=%v", i, rtt)
	}
}
