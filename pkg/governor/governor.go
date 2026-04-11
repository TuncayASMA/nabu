// Package governor provides a lightweight adaptive-rate controller for NABU.
// It reads /proc/net/dev to measure real-time interface throughput and applies
// a time-of-day coefficient so that NABU traffic mirrors the diurnal rhythm of
// organic internet traffic — a key DPI-evasion property.
//
// This is the Faz-2 (non-eBPF) implementation.  eBPF-based kernel hooking is
// planned for Faz 3 (Sprint 17–18).
package governor

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultProcNetDev is the path to the Linux network-statistics file.
const DefaultProcNetDev = "/proc/net/dev"

// TimeOfDayCoeff returns a multiplier in [0.3, 1.0] that scales the target
// tunnel bandwidth based on the local hour of day.  It models a typical
// residential-internet diurnal curve: low overnight, peak in the evening.
//
// hour  0: 0.30  (deep night, minimal traffic)
// hour  8: 0.50  (morning ramp-up)
// hour 12: 0.70  (midday)
// hour 20: 1.00  (prime time peak)
// hour 23: 0.60  (late night wind-down)
//
// The curve is computed as a truncated cosine shifted to peak at 20:
//
// raw(h) = 0.5 * (1 - cos(2π * (h-8)/24)) for h in [0,24)
// coeff  = clamp(raw, 0.30, 1.00)
func TimeOfDayCoeff(t time.Time) float64 {
	h := float64(t.Hour()) + float64(t.Minute())/60.0
	// Shift so that h=20 maps to cos(π) = -1 → raw = 1.0
	// peak at h=20: angle = π when h=20 → shift = 8 makes angle=2π*(8)/24=2π/3... let me use direct formula
	// Use: peak at 20, trough at 8; period 24h
	// f(h) = 0.5*(1 - cos(2π*(h-20)/24))  → f(20)=1, f(8)=0
	raw := 0.5 * (1 - math.Cos(2*math.Pi*(h-8)/24))
	if raw < 0.30 {
		return 0.30
	}
	if raw > 1.00 {
		return 1.00
	}
	return raw
}

// InterfaceStats holds the cumulative byte/packet counters for one NIC,
// parsed from /proc/net/dev.
type InterfaceStats struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
	RxPkts  uint64
	TxPkts  uint64
}

// ReadProcNetDev parses the given /proc/net/dev file and returns a map of
// interface name → InterfaceStats.
func ReadProcNetDev(path string) (map[string]InterfaceStats, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("governor: open %s: %w", path, err)
	}
	defer f.Close()

	result := make(map[string]InterfaceStats)
	scanner := bufio.NewScanner(f)

	// Skip the two header lines.
	for i := 0; i < 2; i++ {
		if !scanner.Scan() {
			return result, nil
		}
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		// /proc/net/dev columns after colon:
		// RxBytes RxPkts RxErrs RxDrop RxFifo RxFrame RxCompressed RxMcast
		// TxBytes TxPkts TxErrs TxDrop TxFifo TxColls TxCarrier TxCompressed
		if len(fields) < 16 {
			continue
		}
		parse := func(s string) uint64 {
			v, _ := strconv.ParseUint(s, 10, 64)
			return v
		}
		result[name] = InterfaceStats{
			Name:    name,
			RxBytes: parse(fields[0]),
			RxPkts:  parse(fields[1]),
			TxBytes: parse(fields[8]),
			TxPkts:  parse(fields[9]),
		}
	}
	return result, scanner.Err()
}

// Snapshot captures a throughput measurement at one point in time.
type Snapshot struct {
	At    time.Time
	Stats map[string]InterfaceStats
}

// ThroughputBps holds the computed per-interface throughput.
type ThroughputBps struct {
	Iface    string
	RxBytesS float64 // receive bytes/s
	TxBytesS float64 // transmit bytes/s
}

// ComputeThroughput computes per-interface bytes/s between two snapshots.
// Interfaces present in both snapshots are returned; counter wraps are treated
// as 0 for safety.
func ComputeThroughput(a, b Snapshot) []ThroughputBps {
	dt := b.At.Sub(a.At).Seconds()
	if dt <= 0 {
		return nil
	}
	var out []ThroughputBps
	for name, bStat := range b.Stats {
		aStat, ok := a.Stats[name]
		if !ok {
			continue
		}
		rxDelta := safeDelta(bStat.RxBytes, aStat.RxBytes)
		txDelta := safeDelta(bStat.TxBytes, aStat.TxBytes)
		out = append(out, ThroughputBps{
			Iface:    name,
			RxBytesS: float64(rxDelta) / dt,
			TxBytesS: float64(txDelta) / dt,
		})
	}
	return out
}

func safeDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return 0 // counter wrap — treat conservatively
}

// Config holds tunable Governor parameters.
type Config struct {
	// ProcPath is the path to /proc/net/dev (override for tests).
	ProcPath string
	// Interface is the NIC to track.  If empty, the first non-loopback
	// interface with nonzero traffic is used.
	Interface string
	// MaxBandwidthBps is the absolute bandwidth ceiling (bytes/s).
	// 0 means unlimited (default: 10 MiB/s = 10_485_760).
	MaxBandwidthBps float64
	// PollInterval is how often to read /proc/net/dev (default: 2s).
	PollInterval time.Duration
	// NowFunc is injectable for tests; defaults to time.Now.
	NowFunc func() time.Time
}

func (c *Config) defaults() {
	if c.ProcPath == "" {
		c.ProcPath = DefaultProcNetDev
	}
	if c.MaxBandwidthBps == 0 {
		c.MaxBandwidthBps = 10 * 1024 * 1024
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.NowFunc == nil {
		c.NowFunc = time.Now
	}
}

// Recommendation is the Governor's output for each polling tick.
type Recommendation struct {
	// TargetBytesS is the suggested tunnel bandwidth (bytes/s) accounting for
	// the time-of-day coefficient and current interface utilisation.
	TargetBytesS float64
	// TODCoeff is the time-of-day multiplier that was applied.
	TODCoeff float64
	// ObservedRxBytesS is the current interface receive throughput.
	ObservedRxBytesS float64
	// ObservedTxBytesS is the current interface transmit throughput.
	ObservedTxBytesS float64
	// At is when this recommendation was computed.
	At time.Time
}

// Governor watches /proc/net/dev and emits Recommendations via a channel.
type Governor struct {
	cfg     Config
	mu      sync.RWMutex
	lastRec *Recommendation
}

// New creates a Governor from cfg.  cfg is normalised to defaults before use.
func New(cfg Config) *Governor {
	cfg.defaults()
	return &Governor{cfg: cfg}
}

// LastRecommendation returns the most recently computed Recommendation.
// Returns nil if Run has not been called or no tick has occurred yet.
func (g *Governor) LastRecommendation() *Recommendation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastRec
}

// Run starts the polling loop.  It blocks until ctx is cancelled.
// Each recommendation is sent on the returned channel (buffered, size 1).
// If the consumer is slow, old values are dropped (non-blocking send).
func (g *Governor) Run(ctx context.Context) <-chan Recommendation {
	ch := make(chan Recommendation, 1)
	go g.loop(ctx, ch)
	return ch
}

func (g *Governor) loop(ctx context.Context, ch chan<- Recommendation) {
	defer close(ch)

	prev, err := g.snapshot()
	if err != nil {
		// /proc not available (e.g., non-Linux); emit zero recommendation.
		prev = Snapshot{At: g.cfg.NowFunc()}
	}

	ticker := time.NewTicker(g.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, err := g.snapshot()
			if err != nil {
				cur = Snapshot{At: g.cfg.NowFunc(), Stats: prev.Stats}
			}

			rec := g.compute(prev, cur)
			prev = cur

			g.mu.Lock()
			g.lastRec = &rec
			g.mu.Unlock()

			// Non-blocking send: drop if no consumer is ready.
			select {
			case ch <- rec:
			default:
			}
		}
	}
}

func (g *Governor) snapshot() (Snapshot, error) {
	stats, err := ReadProcNetDev(g.cfg.ProcPath)
	return Snapshot{At: g.cfg.NowFunc(), Stats: stats}, err
}

func (g *Governor) compute(prev, cur Snapshot) Recommendation {
	tps := ComputeThroughput(prev, cur)

	var rxBps, txBps float64
	for _, tp := range tps {
		if g.cfg.Interface != "" {
			if tp.Iface == g.cfg.Interface {
				rxBps = tp.RxBytesS
				txBps = tp.TxBytesS
				break
			}
		} else {
			// Pick first non-loopback interface with nonzero traffic.
			if tp.Iface != "lo" && (tp.RxBytesS > 0 || tp.TxBytesS > 0) {
				rxBps = tp.RxBytesS
				txBps = tp.TxBytesS
				break
			}
		}
	}

	tod := TimeOfDayCoeff(cur.At)
	target := g.cfg.MaxBandwidthBps * tod

	return Recommendation{
		TargetBytesS:     target,
		TODCoeff:         tod,
		ObservedRxBytesS: rxBps,
		ObservedTxBytesS: txBps,
		At:               cur.At,
	}
}
