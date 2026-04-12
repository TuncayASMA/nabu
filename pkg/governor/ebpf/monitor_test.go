package ebpf_test

import (
	"context"
	"testing"
	"time"

	nabuebpf "github.com/TuncayASMA/nabu/pkg/governor/ebpf"
)

// All tests use the stub backend (no kernel privs required).

func TestMonitor_NewMonitor(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 64)
	if m == nil {
		t.Fatal("NewMonitor returned nil")
	}
}

func TestMonitor_StartStop(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 64)
	ctx := context.Background()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestMonitor_StartIdempotent(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 64)
	ctx := context.Background()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("second Start should be no-op: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestMonitor_StopWithoutStart(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 64)
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop without Start should be no-op: %v", err)
	}
}

func TestMonitor_SnapshotZero(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 64)
	ctx := context.Background()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		if err := m.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()

	snap := m.Snapshot()
	if snap.Ingress.Packets != 0 || snap.Egress.Packets != 0 {
		t.Errorf("expected zero counters on stub, got ingress=%+v egress=%+v",
			snap.Ingress, snap.Egress)
	}
}

func TestMonitor_SnapshotTimestamp(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 8)
	ctx := context.Background()

	before := time.Now()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	snap := m.Snapshot()
	after := time.Now()

	if snap.At.Before(before) || snap.At.After(after) {
		t.Errorf("Snapshot.At %v not in [%v, %v]", snap.At, before, after)
	}

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestMonitor_EventsChannel(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 64)
	ch := m.Events()
	if ch == nil {
		t.Fatal("Events() returned nil channel")
	}
}

func TestMonitor_EventsChannelNoLeakAfterStop(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 4)
	ctx := context.Background()

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// After Stop the stub readEvents goroutine must have exited.
	// We can verify by starting a second time (would deadlock if goroutine leaked).
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Restart after Stop: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Second Stop: %v", err)
	}
}

func TestIsStub(t *testing.T) {
	if !nabuebpf.IsStub() {
		t.Error("expected IsStub()=true without bpf2go-generated objects")
	}
}

func TestDirection_Constants(t *testing.T) {
	if nabuebpf.Ingress != 0 {
		t.Errorf("Ingress should be 0, got %d", nabuebpf.Ingress)
	}
	if nabuebpf.Egress != 1 {
		t.Errorf("Egress should be 1, got %d", nabuebpf.Egress)
	}
}

func TestSnapshot_Fields(t *testing.T) {
	snap := nabuebpf.Snapshot{}
	_ = snap.Ingress.Packets
	_ = snap.Ingress.Bytes
	_ = snap.Egress.Packets
	_ = snap.Egress.Bytes
	_ = snap.At
}

func TestEvent_Fields(t *testing.T) {
	ev := nabuebpf.Event{
		TimestampNS: 1_000_000,
		IATNS:       50_000,
		PktLen:      1500,
		Direction:   nabuebpf.Egress,
	}
	if ev.TimestampNS == 0 {
		t.Error("TimestampNS should be set")
	}
	if ev.IATNS == 0 {
		t.Error("IATNS should be set")
	}
	if ev.PktLen == 0 {
		t.Error("PktLen should be set")
	}
	if ev.Direction != nabuebpf.Egress {
		t.Errorf("unexpected direction: %v", ev.Direction)
	}
}

func TestMonitor_CancelContext(t *testing.T) {
	m := nabuebpf.NewMonitor("lo", 8)
	ctx, cancel := context.WithCancel(context.Background())

	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Cancel the parent context — Stop should still work cleanly.
	cancel()
	time.Sleep(10 * time.Millisecond) // let goroutines react

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop after cancel: %v", err)
	}
}
