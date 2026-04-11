package multipath

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// startEchoServer starts a simple UDP echo server on an OS-assigned port.
// Returns the listen address and a stop function.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() } //nolint:errcheck
}

// ---------------------------------------------------------------------------
// deriveProbeAddr tests
// ---------------------------------------------------------------------------

func TestDeriveProbeAddr_Basic(t *testing.T) {
	got, err := deriveProbeAddr("127.0.0.1:7001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// probe port = 7001 + 1000 = 8001
	want := "127.0.0.1:8001"
	if got != want {
		t.Errorf("deriveProbeAddr: got %q want %q", got, want)
	}
}

func TestDeriveProbeAddr_IPv6(t *testing.T) {
	got, err := deriveProbeAddr("[::1]:7002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "[::1]:8002"
	if got != want {
		t.Errorf("deriveProbeAddr IPv6: got %q want %q", got, want)
	}
}

func TestDeriveProbeAddr_BadAddr(t *testing.T) {
	_, err := deriveProbeAddr("not-an-addr")
	if err == nil {
		t.Error("expected error for bad addr, got nil")
	}
}

// ---------------------------------------------------------------------------
// MultiPathConn construction & Stats tests
// ---------------------------------------------------------------------------

func TestMultiPathConn_InitialStats(t *testing.T) {
	eps := []RelayEndpoint{
		{ID: 0, Addr: "127.0.0.1:7001"},
		{ID: 1, Addr: "127.0.0.1:7002"},
	}
	m := NewMultiPathConn(eps, nil, PingOptions{})

	stats := m.Stats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats, got %d", len(stats))
	}
	for i, s := range stats {
		if s.Available {
			t.Errorf("stat[%d]: expected unavailable initially, got available", i)
		}
		if s.RTT != 10*time.Second {
			t.Errorf("stat[%d]: expected 10s sentinel RTT, got %v", i, s.RTT)
		}
	}
}

func TestMultiPathConn_UpdateStats(t *testing.T) {
	eps := []RelayEndpoint{
		{ID: 0, Addr: "127.0.0.1:7001"},
	}
	m := NewMultiPathConn(eps, nil, PingOptions{})

	m.UpdateStats(0, 20*time.Millisecond, 1_000_000, 0.01)

	stats := m.Stats()
	if !stats[0].Available {
		t.Error("path should be available after UpdateStats")
	}
	if stats[0].RTT != 20*time.Millisecond {
		t.Errorf("expected RTT 20ms, got %v", stats[0].RTT)
	}
	if stats[0].Bandwidth != 1_000_000 {
		t.Errorf("expected BW 1e6, got %d", stats[0].Bandwidth)
	}
}

func TestMultiPathConn_UpdateStats_OutOfRange(t *testing.T) {
	// Should not panic for out-of-range index.
	m := NewMultiPathConn([]RelayEndpoint{{ID: 0, Addr: "127.0.0.1:7001"}}, nil, PingOptions{})
	m.UpdateStats(-1, time.Second, 0, 0)
	m.UpdateStats(99, time.Second, 0, 0)
}

// ---------------------------------------------------------------------------
// SelectPath tests (via UpdateStats to inject known good state)
// ---------------------------------------------------------------------------

func TestMultiPathConn_SelectPath_PreferLowRTT(t *testing.T) {
	eps := []RelayEndpoint{
		{ID: 0, Addr: "127.0.0.1:7001"},
		{ID: 1, Addr: "127.0.0.1:7002"},
	}
	m := NewMultiPathConn(eps, NewMinRTT(), PingOptions{})

	m.UpdateStats(0, 80*time.Millisecond, 1e6, 0)
	m.UpdateStats(1, 20*time.Millisecond, 1e6, 0)

	idx, ep := m.SelectPath()
	if idx != 1 {
		t.Errorf("expected index 1 (lower RTT), got %d", idx)
	}
	if ep.ID != 1 {
		t.Errorf("expected endpoint ID 1, got %d", ep.ID)
	}
}

func TestMultiPathConn_SelectPath_NoneAvailable(t *testing.T) {
	eps := []RelayEndpoint{{ID: 0, Addr: "127.0.0.1:7001"}}
	m := NewMultiPathConn(eps, nil, PingOptions{})
	// No UpdateStats call → all unavailable.
	idx, ep := m.SelectPath()
	if idx != -1 {
		t.Errorf("expected -1, got %d", idx)
	}
	if ep.Addr != "" {
		t.Errorf("expected empty endpoint, got %+v", ep)
	}
}

func TestMultiPathConn_SelectPath_Empty(t *testing.T) {
	m := NewMultiPathConn(nil, nil, PingOptions{})
	idx, _ := m.SelectPath()
	if idx != -1 {
		t.Errorf("empty endpoints: expected -1, got %d", idx)
	}
}

// ---------------------------------------------------------------------------
// Probe / Start / Stop tests
// ---------------------------------------------------------------------------

// TestMultiPathConn_ProbeReachable starts a real UDP echo server on the probe
// port (relay_port + 1000) and verifies that after a probe round the path
// transitions to Available=true with a reasonable RTT.
func TestMultiPathConn_ProbeReachable(t *testing.T) {
	// Start echo server on, e.g., 127.0.0.1:XXXXX.
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	// Derive relay addr so that probe_port = echoPort (relay_port + 1000).
	// i.e., relay_port = echoPort - 1000.
	_, portStr, _ := net.SplitHostPort(echoAddr)
	var echoPort int
	_, _ = fmt.Sscanf(portStr, "%d", &echoPort) //nolint:errcheck
	if echoPort <= 1000 {
		t.Skip("echo port ≤ 1000 — can't derive relay port (skip)")
	}
	relayPort := echoPort - 1000
	relayAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", relayPort))

	eps := []RelayEndpoint{{ID: 0, Addr: relayAddr}}
	opts := PingOptions{
		Interval:       100 * time.Millisecond,
		Timeout:        500 * time.Millisecond,
		ProbesPerRound: 1,
	}
	m := NewMultiPathConn(eps, nil, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m.Start(ctx)
	defer m.Stop()

	// Wait up to 1s for the first probe to complete.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats := m.Stats()
		if stats[0].Available {
			t.Logf("path available after probe, RTT=%v", stats[0].RTT)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Error("path did not become available after 1s of probing")
}

// TestMultiPathConn_ProbeUnreachable verifies that an unreachable relay keeps
// Available=false after the probe timeout.
func TestMultiPathConn_ProbeUnreachable(t *testing.T) {
	// Use a port that is almost certainly not listening.
	eps := []RelayEndpoint{{ID: 0, Addr: "127.0.0.1:59999"}}
	opts := PingOptions{
		Interval:       50 * time.Millisecond,
		Timeout:        50 * time.Millisecond,
		ProbesPerRound: 1,
	}
	m := NewMultiPathConn(eps, nil, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	m.Start(ctx)
	<-ctx.Done()
	m.Stop()

	stats := m.Stats()
	if stats[0].Available {
		t.Error("unreachable relay should remain unavailable")
	}
}

// TestMultiPathConn_StartIdempotent verifies Start is idempotent (calling
// it twice does not spawn duplicate goroutines or panic).
func TestMultiPathConn_StartIdempotent(t *testing.T) {
	eps := []RelayEndpoint{{ID: 0, Addr: "127.0.0.1:7001"}}
	m := NewMultiPathConn(eps, nil, PingOptions{Interval: 10 * time.Second, Timeout: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	m.Start(ctx) // second call should be a no-op
	cancel()
	m.Stop()
}
