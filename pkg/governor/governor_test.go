package governor_test

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/governor"
)

// ----- TimeOfDayCoeff -----

func TestTimeOfDayCoeff_Peak(t *testing.T) {
	// Peak at 20:00 → coefficient should be 1.0.
	ts := time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC)
	got := governor.TimeOfDayCoeff(ts)
	if math.Abs(got-1.0) > 1e-9 {
		t.Fatalf("peak coeff: want 1.0, got %.6f", got)
	}
}

func TestTimeOfDayCoeff_NightFloor(t *testing.T) {
	// Trough at 08:00 → raw=0, clamped to 0.30.
	ts := time.Date(2024, 1, 1, 8, 0, 0, 0, time.UTC)
	got := governor.TimeOfDayCoeff(ts)
	if math.Abs(got-0.30) > 0.01 {
		t.Fatalf("trough coeff: want ≈0.30, got %.6f", got)
	}
}

func TestTimeOfDayCoeff_Range(t *testing.T) {
	for h := 0; h < 24; h++ {
		ts := time.Date(2024, 1, 1, h, 0, 0, 0, time.UTC)
		c := governor.TimeOfDayCoeff(ts)
		if c < 0.30 || c > 1.0 {
			t.Errorf("hour %d: coeff %.4f outside [0.30, 1.00]", h, c)
		}
	}
}

func TestTimeOfDayCoeff_Midnight(t *testing.T) {
	// At midnight h=0: raw = 0.5*(1-cos(2π*(-8)/24)) = 0.5*(1-cos(-2π/3)) ≈ 0.75
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := governor.TimeOfDayCoeff(ts)
	if c < 0.30 || c > 1.00 {
		t.Errorf("midnight coeff %.4f not in [0.30, 1.00]", c)
	}
}

// ----- ReadProcNetDev (using fake file) -----

func writeFakeProc(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "net_dev")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writeFakeProc: %v", err)
	}
	return p
}

const fakeProc = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456      100    0    0    0     0          0         0  123456      100    0    0    0     0       0          0
  eth0: 9876543     8765   0    0    0     0          0         0 1234567     4321   0    0    0     0       0          0
`

func TestReadProcNetDev_ParsesFields(t *testing.T) {
	p := writeFakeProc(t, fakeProc)
	stats, err := governor.ReadProcNetDev(p)
	if err != nil {
		t.Fatalf("ReadProcNetDev: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("want 2 interfaces, got %d", len(stats))
	}
	eth0, ok := stats["eth0"]
	if !ok {
		t.Fatal("eth0 not found")
	}
	if eth0.RxBytes != 9876543 {
		t.Errorf("eth0 RxBytes: want 9876543, got %d", eth0.RxBytes)
	}
	if eth0.TxBytes != 1234567 {
		t.Errorf("eth0 TxBytes: want 1234567, got %d", eth0.TxBytes)
	}
}

func TestReadProcNetDev_Loopback(t *testing.T) {
	p := writeFakeProc(t, fakeProc)
	stats, err := governor.ReadProcNetDev(p)
	if err != nil {
		t.Fatalf("ReadProcNetDev: %v", err)
	}
	lo, ok := stats["lo"]
	if !ok {
		t.Fatal("lo not found")
	}
	if lo.RxBytes != 123456 {
		t.Errorf("lo RxBytes: want 123456, got %d", lo.RxBytes)
	}
}

func TestReadProcNetDev_BadPath(t *testing.T) {
	_, err := governor.ReadProcNetDev("/nonexistent/path/net_dev")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

// ----- ComputeThroughput -----

func makeSnap(at time.Time, iface string, rx, tx uint64) governor.Snapshot {
	return governor.Snapshot{
		At: at,
		Stats: map[string]governor.InterfaceStats{
			iface: {Name: iface, RxBytes: rx, TxBytes: tx},
		},
	}
}

func TestComputeThroughput_Basic(t *testing.T) {
	t0 := time.Unix(0, 0)
	t1 := t0.Add(2 * time.Second)
	a := makeSnap(t0, "eth0", 0, 0)
	b := makeSnap(t1, "eth0", 20000, 10000)
	tps := governor.ComputeThroughput(a, b)
	if len(tps) != 1 {
		t.Fatalf("want 1 result, got %d", len(tps))
	}
	if math.Abs(tps[0].RxBytesS-10000) > 0.1 {
		t.Errorf("RxBytesS: want 10000, got %.2f", tps[0].RxBytesS)
	}
	if math.Abs(tps[0].TxBytesS-5000) > 0.1 {
		t.Errorf("TxBytesS: want 5000, got %.2f", tps[0].TxBytesS)
	}
}

func TestComputeThroughput_ZeroDt(t *testing.T) {
	now := time.Now()
	a := makeSnap(now, "eth0", 0, 0)
	b := makeSnap(now, "eth0", 1000, 500)
	tps := governor.ComputeThroughput(a, b)
	if len(tps) != 0 {
		t.Fatalf("want no results for zero dt, got %d", len(tps))
	}
}

func TestComputeThroughput_CounterWrap(t *testing.T) {
	t0 := time.Unix(0, 0)
	t1 := t0.Add(time.Second)
	// Simulate counter wrap: cur < prev → delta = 0.
	a := makeSnap(t0, "eth0", 1000, 500)
	b := makeSnap(t1, "eth0", 100, 50) // wrapped
	tps := governor.ComputeThroughput(a, b)
	if len(tps) != 1 {
		t.Fatalf("want 1 result, got %d", len(tps))
	}
	if tps[0].RxBytesS != 0 {
		t.Errorf("counter wrap: expect RxBytesS=0, got %.2f", tps[0].RxBytesS)
	}
}

// ----- Governor.Run -----

func fakeNetDev(t *testing.T, rx1, tx1, rx2, tx2 uint64) (path string, advance func()) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "net_dev")

	writeFile := func(rx, tx uint64) {
		content := fmt.Sprintf(
			"Inter-|   Receive                                                |  Transmit\n"+
				" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
				"  eth0: %d      1000    0    0    0     0          0         0 %d      500   0    0    0     0       0          0\n",
			rx, tx,
		)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("fakeNetDev write: %v", err)
		}
	}
	writeFile(rx1, tx1)
	adv := func() { writeFile(rx2, tx2) }
	return p, adv
}

func TestGovernorRun_EmitsRecommendation(t *testing.T) {
	procPath, advance := fakeNetDev(t, 0, 0, 10_000_000, 5_000_000)

	fixedTime := time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC) // TOD coeff = 1.0
	tick := 0
	cfg := governor.Config{
		ProcPath:        procPath,
		Interface:       "eth0",
		MaxBandwidthBps: 10 * 1024 * 1024,
		PollInterval:    20 * time.Millisecond,
		NowFunc: func() time.Time {
			tick++
			// advance file on second call so ComputeThroughput sees a delta
			if tick == 2 {
				advance()
			}
			return fixedTime.Add(time.Duration(tick) * time.Second)
		},
	}

	g := governor.New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := g.Run(ctx)
	var rec governor.Recommendation
	select {
	case r, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before first recommendation")
		}
		rec = r
	case <-time.After(400 * time.Millisecond):
		t.Fatal("timeout waiting for first recommendation")
	}

	if math.Abs(rec.TODCoeff-1.0) > 0.01 {
		t.Errorf("TODCoeff: want ≈1.0, got %.4f", rec.TODCoeff)
	}
	expectedTarget := 10.0 * 1024 * 1024 * rec.TODCoeff
	if math.Abs(rec.TargetBytesS-expectedTarget) > 1 {
		t.Errorf("TargetBytesS: want %.0f, got %.0f", expectedTarget, rec.TargetBytesS)
	}
}

func TestGovernorRun_CancelsCleanly(t *testing.T) {
	procPath, _ := fakeNetDev(t, 0, 0, 0, 0)
	cfg := governor.Config{
		ProcPath:     procPath,
		PollInterval: 10 * time.Millisecond,
	}
	g := governor.New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	ch := g.Run(ctx)
	cancel()
	// Drain and wait for close.
	for range ch {
	}
	// If we get here the goroutine exited cleanly.
}

func TestGovernorRun_LastRecommendation(t *testing.T) {
	procPath, _ := fakeNetDev(t, 0, 0, 0, 0)
	cfg := governor.Config{
		ProcPath:     procPath,
		PollInterval: 20 * time.Millisecond,
	}
	g := governor.New(cfg)
	if g.LastRecommendation() != nil {
		t.Fatal("LastRecommendation should be nil before Run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ch := g.Run(ctx)
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
	}
	<-ctx.Done()
	for range ch {
	}
	// After at least one tick, LastRecommendation is non-nil.
	rec := g.LastRecommendation()
	if rec == nil {
		t.Fatal("LastRecommendation nil after run produced ticks")
	}
}
