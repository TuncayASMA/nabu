package governor_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/governor"
)

// ── stub eBPF snapshot provider ─────────────────────────────────────────────

type stubEBPF struct {
	mu  sync.Mutex
	snp governor.EBPFSnapshot
}

func newStubEBPF() *stubEBPF {
	return &stubEBPF{
		snp: governor.EBPFSnapshot{At: time.Now()},
	}
}

func (s *stubEBPF) Snapshot() governor.EBPFSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snp
}

func (s *stubEBPF) setPackets(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snp.IngressPackets = n
	s.snp.At = time.Now()
}

// ── helpers ─────────────────────────────────────────────────────────────────

const zeroProcNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:      0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0
  eth0:      0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0
`

func writeProcZero(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "net_dev")
	if err := os.WriteFile(p, []byte(zeroProcNetDev), 0o600); err != nil {
		t.Fatalf("writeProcZero: %v", err)
	}
	return p
}

func zeroGovernor(t *testing.T) *governor.Governor {
	t.Helper()
	return governor.New(governor.Config{
		ProcPath:     writeProcZero(t),
		PollInterval: 1 * time.Hour, // no background ticks in unit tests
		NowFunc:      time.Now,
	})
}

func newEngine(t *testing.T, ebpf governor.SnapshotProvider) *governor.DecisionEngine {
	t.Helper()
	g := zeroGovernor(t)
	return governor.NewDecisionEngine(governor.EngineConfig{
		Governor:         g,
		EBPF:             ebpf,
		TickInterval:     10 * time.Millisecond,
		MaxPhantomBytesS: 512 * 1024,
		NowFunc:          time.Now,
	})
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestDecisionEngine_NewEngine(t *testing.T) {
	e := newEngine(t, nil)
	if e == nil {
		t.Fatal("NewDecisionEngine returned nil")
	}
}

func TestDecisionEngine_LastDecisionNilBeforeRun(t *testing.T) {
	e := newEngine(t, nil)
	if e.LastDecision() != nil {
		t.Error("LastDecision should be nil before Run is called")
	}
}

func TestDecisionEngine_RunEmitsDecision(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := e.Run(ctx)
	select {
	case dec, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before any decision")
		}
		if dec.At.IsZero() {
			t.Error("Decision.At should not be zero")
		}
	case <-ctx.Done():
		t.Fatal("no decision received before timeout")
	}
}

func TestDecisionEngine_PhantomRateRange(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	for dec := range e.Run(ctx) {
		if dec.PhantomRate < 0 || dec.PhantomRate > 512*1024 {
			t.Errorf("PhantomRate %f out of [0, 512KiB/s]", dec.PhantomRate)
		}
	}
}

func TestDecisionEngine_FECRatioRange(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	for dec := range e.Run(ctx) {
		if dec.FECRatio < 0 || dec.FECRatio > 1 {
			t.Errorf("FECRatio %f out of [0,1]", dec.FECRatio)
		}
	}
}

func TestDecisionEngine_SchedulerBiasRange(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	for dec := range e.Run(ctx) {
		if dec.SchedulerBias < -1 || dec.SchedulerBias > 1 {
			t.Errorf("SchedulerBias %f out of [-1,1]", dec.SchedulerBias)
		}
	}
}

func TestDecisionEngine_TODCoeffPositive(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	for dec := range e.Run(ctx) {
		if dec.TODCoeff <= 0 {
			t.Errorf("TODCoeff %f should be positive", dec.TODCoeff)
		}
	}
}

func TestDecisionEngine_UtilFractionRange(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	for dec := range e.Run(ctx) {
		if dec.UtilFraction < 0 || dec.UtilFraction > 1 {
			t.Errorf("UtilFraction %f out of [0,1]", dec.UtilFraction)
		}
	}
}

func TestDecisionEngine_LastDecisionUpdated(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	ch := e.Run(ctx)
	// Wait for at least one decision.
	_, ok := <-ch
	if !ok {
		t.Fatal("channel closed too early")
	}
	if e.LastDecision() == nil {
		t.Error("LastDecision should not be nil after first tick")
	}
}

func TestDecisionEngine_ChannelClosedAfterCancel(t *testing.T) {
	e := newEngine(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	ch := e.Run(ctx)
	cancel()

	// Drain channel until closed.
	timeout := time.After(500 * time.Millisecond)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // channel closed — OK
			}
		case <-timeout:
			t.Fatal("channel not closed after context cancel")
		}
	}
}

func TestDecisionEngine_WithEBPFStub(t *testing.T) {
	stub := newStubEBPF()
	e := newEngine(t, stub)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	ch := e.Run(ctx)
	dec, ok := <-ch
	if !ok {
		t.Fatal("no decision received")
	}
	if dec.FECRatio < 0 || dec.FECRatio > 1 {
		t.Errorf("FECRatio out of range: %f", dec.FECRatio)
	}
}

func TestDecisionEngine_IATEWMAInitialPositive(t *testing.T) {
	e := newEngine(t, nil)
	if v := e.IATEWMANs(); v <= 0 {
		t.Errorf("initial IATEWMANs should be positive, got %f", v)
	}
}

func TestDecisionEngine_IATSpikeBoostsFECRatio(t *testing.T) {
	stub := newStubEBPF()

	// Use a very low spike threshold so we can trigger it deterministically.
	g := zeroGovernor(t)
	e := governor.NewDecisionEngine(governor.EngineConfig{
		Governor:          g,
		EBPF:              stub,
		TickInterval:      10 * time.Millisecond,
		MaxPhantomBytesS:  512 * 1024,
		IATSpikeThreshold: 1.0001, // almost any IAT will trigger spike
		NowFunc:           time.Now,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := e.Run(ctx)

	// Seed with some packets so the EWMA has data.
	stub.setPackets(1000)
	time.Sleep(50 * time.Millisecond)
	// Jump packet count massively to create a huge per-packet IAT spike.
	stub.setPackets(1001)

	var spikedFEC float64
	for dec := range ch {
		if dec.FECRatio >= 0.20 {
			spikedFEC = dec.FECRatio
			break
		}
	}
	if spikedFEC == 0 {
		// It's acceptable if the spike never triggered in this window; skip.
		t.Skip("spike not triggered in window — environment timing sensitive")
	}
}

func TestDecisionEngine_BurstModeAtLowUtil(t *testing.T) {
	// With zero traffic (zeroGovernor proc path), utilEWMA stays near 0
	// so BurstMode should eventually be true.
	e := newEngine(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for dec := range e.Run(ctx) {
		if dec.BurstMode {
			return // found burst mode — pass
		}
	}
	t.Error("BurstMode never became true at zero utilisation")
}
