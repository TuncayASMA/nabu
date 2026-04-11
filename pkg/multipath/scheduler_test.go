package multipath

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func path(id uint32, rtt time.Duration, bw uint64, loss float64, available bool) PathStats {
	return PathStats{
		ID:        id,
		RTT:       rtt,
		Bandwidth: bw,
		LossRate:  loss,
		Available: available,
	}
}

// ---------------------------------------------------------------------------
// MinRTTScheduler tests
// ---------------------------------------------------------------------------

func TestMinRTT_SelectsLowestRTT(t *testing.T) {
	s := NewMinRTT()
	paths := []PathStats{
		path(1, ms(50), 1e6, 0, true),
		path(2, ms(20), 1e6, 0, true),
		path(3, ms(80), 1e6, 0, true),
	}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("expected index 1 (RTT=20ms), got %d", idx)
	}
}

func TestMinRTT_SkipsUnavailable(t *testing.T) {
	s := NewMinRTT()
	paths := []PathStats{
		path(1, ms(10), 1e6, 0, false), // lowest RTT but unavailable
		path(2, ms(30), 1e6, 0, true),
		path(3, ms(50), 1e6, 0, true),
	}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("expected index 1 (lowest available RTT=30ms), got %d", idx)
	}
}

func TestMinRTT_AllUnavailable(t *testing.T) {
	s := NewMinRTT()
	paths := []PathStats{
		path(1, ms(10), 1e6, 0, false),
		path(2, ms(30), 1e6, 0, false),
	}
	if got := s.SelectPath(paths); got != -1 {
		t.Errorf("expected -1 for all unavailable, got %d", got)
	}
}

func TestMinRTT_EmptyPaths(t *testing.T) {
	s := NewMinRTT()
	if got := s.SelectPath(nil); got != -1 {
		t.Errorf("expected -1 for nil paths, got %d", got)
	}
}

func TestMinRTT_EWMASmooths(t *testing.T) {
	s := NewMinRTT()
	// First call: both equal RTT — should be stable (idx=0 wins tie).
	paths := []PathStats{
		path(1, ms(50), 1e6, 0, true),
		path(2, ms(50), 1e6, 0, true),
	}
	idx := s.SelectPath(paths)
	if idx != 0 {
		t.Errorf("tie: expected index 0, got %d", idx)
	}

	// Now path 2 gets a lower RTT — EWMA must update; path 2 should win
	// after sufficient calls.
	for i := 0; i < 20; i++ {
		paths[0] = path(1, ms(100), 1e6, 0, true)
		paths[1] = path(2, ms(5), 1e6, 0, true)
		s.SelectPath(paths)
	}
	// Final call: path 2 EWMA < path 1 EWMA.
	paths[0] = path(1, ms(100), 1e6, 0, true)
	paths[1] = path(2, ms(5), 1e6, 0, true)
	idx = s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("after EWMA convergence expected index 1, got %d", idx)
	}
}

func TestMinRTT_SinglePath(t *testing.T) {
	s := NewMinRTT()
	paths := []PathStats{path(42, ms(25), 5e5, 0.01, true)}
	if got := s.SelectPath(paths); got != 0 {
		t.Errorf("single path: expected 0, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// BLESTScheduler tests
// ---------------------------------------------------------------------------

func TestBLEST_SelectsLowQueuePath(t *testing.T) {
	s := NewBLEST()

	// Path A: moderate RTT, high in-flight relative to bandwidth → high queue depth.
	// Path B: higher RTT but low queue depth → should win.
	pathA := PathStats{ID: 1, RTT: ms(30), Bandwidth: 100_000, InFlight: 100_000, Available: true}
	// queue depth A = 100000/100000 = 1.0 s (huge penalty)
	pathB := PathStats{ID: 2, RTT: ms(60), Bandwidth: 2_000_000, InFlight: 1_000, Available: true}
	// queue depth B ≈ 0.0005 s (tiny penalty)

	paths := []PathStats{pathA, pathB}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("BLEST: expected lower-queue path (index 1), got %d", idx)
	}
}

func TestBLEST_FallbackToMinRTTWhenQueuesEqual(t *testing.T) {
	s := NewBLEST()
	// Both paths have the same zero queue depth; lower RTT path should win.
	paths := []PathStats{
		{ID: 1, RTT: ms(100), Bandwidth: 1e6, InFlight: 0, Available: true},
		{ID: 2, RTT: ms(20), Bandwidth: 1e6, InFlight: 0, Available: true},
	}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("BLEST no queue: expected index 1 (lower RTT), got %d", idx)
	}
}

func TestBLEST_SkipsUnavailable(t *testing.T) {
	s := NewBLEST()
	paths := []PathStats{
		{ID: 1, RTT: ms(5), Bandwidth: 1e6, Available: false},
		{ID: 2, RTT: ms(50), Bandwidth: 1e6, Available: true},
	}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("BLEST unavailable: expected index 1, got %d", idx)
	}
}

func TestBLEST_AllUnavailable(t *testing.T) {
	s := NewBLEST()
	paths := []PathStats{
		{ID: 1, Available: false},
		{ID: 2, Available: false},
	}
	if got := s.SelectPath(paths); got != -1 {
		t.Errorf("BLEST all-unavailable: expected -1, got %d", got)
	}
}

func TestBLEST_LossAdjustedRTT(t *testing.T) {
	s := NewBLEST()
	// Path A: very low raw RTT but 90% loss → effective RTT = 10× raw.
	// Path B: moderate RTT, 0% loss.
	pathA := PathStats{ID: 1, RTT: ms(5), LossRate: 0.9, Bandwidth: 1e6, Available: true}
	pathB := PathStats{ID: 2, RTT: ms(30), LossRate: 0, Bandwidth: 1e6, Available: true}
	// effective RTT A = 5ms / 0.1 = 50ms > 30ms → path B should win.
	paths := []PathStats{pathA, pathB}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("BLEST loss-adjusted: expected index 1, got %d", idx)
	}
}

// ---------------------------------------------------------------------------
// RedundantScheduler tests
// ---------------------------------------------------------------------------

func TestRedundant_SelectAllPaths(t *testing.T) {
	s := NewRedundant(0)
	paths := []PathStats{
		path(1, ms(20), 1e6, 0, true),
		path(2, ms(30), 1e6, 0, false),
		path(3, ms(40), 1e6, 0, true),
	}
	all := s.SelectAllPaths(paths)
	if len(all) != 2 {
		t.Errorf("expected 2 available paths, got %d", len(all))
	}
	if all[0] != 0 || all[1] != 2 {
		t.Errorf("unexpected indices: %v", all)
	}
}

func TestRedundant_MaxCopiesCaps(t *testing.T) {
	s := NewRedundant(2)
	paths := []PathStats{
		path(1, ms(10), 1e6, 0, true),
		path(2, ms(20), 1e6, 0, true),
		path(3, ms(30), 1e6, 0, true),
		path(4, ms(40), 1e6, 0, true),
	}
	all := s.SelectAllPaths(paths)
	if len(all) != 2 {
		t.Errorf("MaxCopies=2: expected 2, got %d", len(all))
	}
}

func TestRedundant_SelectPathDelegatesToPrimary(t *testing.T) {
	s := NewRedundant(0)
	paths := []PathStats{
		path(1, ms(80), 1e6, 0, true),
		path(2, ms(15), 1e6, 0, true),
	}
	idx := s.SelectPath(paths)
	if idx != 1 {
		t.Errorf("redundant single path: expected index 1, got %d", idx)
	}
}

func TestRedundant_NoPaths(t *testing.T) {
	s := NewRedundant(3)
	if got := s.SelectAllPaths(nil); len(got) != 0 {
		t.Errorf("nil paths: expected empty, got %v", got)
	}
	if got := s.SelectPath(nil); got != -1 {
		t.Errorf("nil paths SelectPath: expected -1, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// WeightedRRScheduler tests
// ---------------------------------------------------------------------------

func TestWeightedRR_HighBandwidthWinsMore(t *testing.T) {
	s := NewWeightedRR()
	// Path A: 3× the bandwidth of path B.
	paths := []PathStats{
		{ID: 1, Bandwidth: 3_000_000, Available: true},
		{ID: 2, Bandwidth: 1_000_000, Available: true},
	}

	countA, countB := 0, 0
	for i := 0; i < 400; i++ {
		idx := s.SelectPath(paths)
		switch idx {
		case 0:
			countA++
		case 1:
			countB++
		}
	}
	// Expect ~75:25% split.  Use relaxed bounds (60:40 – 90:10).
	if countA < 240 || countA > 360 {
		t.Errorf("weighted RR: expected ~300 A selections in 400, got %d (B=%d)", countA, countB)
	}
}

func TestWeightedRR_SkipsUnavailable(t *testing.T) {
	s := NewWeightedRR()
	paths := []PathStats{
		{ID: 1, Bandwidth: 1e8, Available: false},
		{ID: 2, Bandwidth: 1, Available: true},
	}
	for i := 0; i < 10; i++ {
		idx := s.SelectPath(paths)
		if idx != 1 {
			t.Errorf("weighted RR unavailable: expected index 1, got %d", idx)
		}
	}
}

func TestWeightedRR_AllUnavailable(t *testing.T) {
	s := NewWeightedRR()
	paths := []PathStats{{ID: 1, Available: false}}
	if got := s.SelectPath(paths); got != -1 {
		t.Errorf("expected -1, got %d", got)
	}
}

func TestWeightedRR_ZeroBandwidth(t *testing.T) {
	// Paths with 0 bandwidth should be treated as 1 byte/s (avoid /0).
	s := NewWeightedRR()
	paths := []PathStats{
		{ID: 1, Bandwidth: 0, Available: true},
		{ID: 2, Bandwidth: 0, Available: true},
	}
	for i := 0; i < 20; i++ {
		idx := s.SelectPath(paths)
		if idx < 0 || idx > 1 {
			t.Errorf("unexpected idx %d", idx)
		}
	}
}
