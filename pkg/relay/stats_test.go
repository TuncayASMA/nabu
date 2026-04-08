package relay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// TestGlobalStatsZeroInitial verifies that a fresh UDPServer has zero counters.
func TestGlobalStatsZeroInitial(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	snap := s.Stats.Snapshot()
	if snap.BytesIn != 0 || snap.BytesOut != 0 || snap.FramesIn != 0 || snap.FramesOut != 0 {
		t.Errorf("expected all-zero stats, got %s", snap.String())
	}
}

// TestGlobalStatsSnapshot checks that Snapshot returns a consistent read.
func TestGlobalStatsSnapshot(t *testing.T) {
	var gs GlobalStats
	gs.BytesIn.Add(100)
	gs.BytesOut.Add(200)
	gs.FramesIn.Add(3)
	gs.FramesOut.Add(4)
	gs.DropsRL.Add(5)

	snap := gs.Snapshot()
	if snap.BytesIn != 100 {
		t.Errorf("BytesIn: want 100, got %d", snap.BytesIn)
	}
	if snap.BytesOut != 200 {
		t.Errorf("BytesOut: want 200, got %d", snap.BytesOut)
	}
	if snap.FramesIn != 3 {
		t.Errorf("FramesIn: want 3, got %d", snap.FramesIn)
	}
	if snap.FramesOut != 4 {
		t.Errorf("FramesOut: want 4, got %d", snap.FramesOut)
	}
	if snap.DropsRL != 5 {
		t.Errorf("DropsRL: want 5, got %d", snap.DropsRL)
	}
}

// TestStatsStringFormat sanity-checks the human-readable summary.
func TestStatsStringFormat(t *testing.T) {
	snap := StatsSnapshot{
		BytesIn:   1024,
		BytesOut:  2048,
		FramesIn:  10,
		FramesOut: 12,
		DropsRL:   2,
	}
	s := snap.String()
	if s == "" {
		t.Fatal("String() returned empty string")
	}
}

// TestFramesInCountedOnReceive verifies that FramesIn increments as frames arrive.
func TestFramesInCountedOnReceive(t *testing.T) {
	srv, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan net.Addr, 1)
	// Patch ListenAddr after creation (Start() will rebind).
	_ = srv

	// Start server on a random port.
	startErr := make(chan error, 1)
	go func() {
		// We need to know which port was assigned — use a helper listener.
		lc := &net.ListenConfig{}
		pc, le := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
		if le != nil {
			startErr <- le
			return
		}
		ready <- pc.LocalAddr()
		pc.Close()
		close(startErr)
	}()

	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("helper listen: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper listen timeout")
	}

	addr := <-ready

	// Create a new server bound to that exact address.
	srv2, err := NewUDPServer(addr.String(), nil)
	if err != nil {
		t.Fatalf("new server2: %v", err)
	}

	serverDone := make(chan error, 1)
	go func() { serverDone <- srv2.Start(ctx) }()

	// Give server time to bind.
	time.Sleep(30 * time.Millisecond)

	// Resolve server address.
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Send a handshake frame (unencrypted, no PSK).
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	frame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagHandshake,
		StreamID: 1,
		Seq:      0,
	}
	raw, err := transport.EncodeFrame(frame)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Wait for the frame to be processed.
	time.Sleep(50 * time.Millisecond)

	cancel() // stop server

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}

	snap := srv2.Stats.Snapshot()
	if snap.FramesIn < 1 {
		t.Errorf("expected FramesIn >= 1, got %d", snap.FramesIn)
	}
}

// TestDropsRLCounted verifies that DropsRL increments when rate limiter fires.
func TestDropsRLCounted(t *testing.T) {
	lc := &net.ListenConfig{}
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-listen: %v", err)
	}
	listenAddr := pc.LocalAddr().String()
	pc.Close()

	srv, err := NewUDPServer(listenAddr, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.RateLimitPPS = 1 // very tight limit

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Start(ctx) }()
	time.Sleep(30 * time.Millisecond)

	udpAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Flood 20 frames — most should be dropped.
	frame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagHandshake,
		StreamID: 1,
		Seq:      0,
	}
	raw, _ := transport.EncodeFrame(frame)
	for i := 0; i < 20; i++ {
		_, _ = conn.Write(raw)
	}
	time.Sleep(80 * time.Millisecond)

	cancel()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}

	snap := srv.Stats.Snapshot()
	if snap.DropsRL == 0 {
		t.Error("expected DropsRL > 0 after flooding with tight rate limit")
	}
	t.Logf("stats: %s", snap.String())
}
