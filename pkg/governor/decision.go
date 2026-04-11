package governor

// Package governor — decision.go: eBPF-aware adaptive decision engine.
//
// DecisionEngine sits on top of the existing Governor (proc/net/dev poller) and
// optionally integrates an eBPF Monitor for kernel-space IAT telemetry.
// Every 100 ms it emits a Decision containing four adaptive outputs:
//
//   PhantomRate   — suggested Phantom traffic injection rate (bytes/s)
//   SchedulerBias — multipath scheduler weight bias in [-1, +1]
//   FECRatio      — forward-error-correction redundancy ratio in [0, 1]
//   BurstMode     — true when link is lightly loaded and bursting is safe
//
// The decision loop uses the eBPF Snapshot (when available) to detect
// inter-arrival-time (IAT) spikes that may indicate DPI probing, and adjusts
// PhantomRate and FECRatio accordingly.

import (
	"context"
	"math"
	"sync"
	"time"
)

// EBPFSnapshot is the subset of the eBPF Monitor Snapshot consumed by the
// decision engine.  Using a small interface instead of a concrete type keeps
// the compile-time dependency on pkg/governor/ebpf optional.
type EBPFSnapshot struct {
	// At is when the snapshot was taken.
	At time.Time
	// IngressPackets / IngressBytes: received traffic since monitor start.
	IngressPackets uint64
	IngressBytes   uint64
	// EgressPackets / EgressBytes: sent traffic since monitor start.
	EgressPackets uint64
	EgressBytes   uint64
}

// SnapshotProvider is implemented by pkg/governor/ebpf.Monitor.
// Accepting an interface avoids a hard dependency and enables stub injection.
type SnapshotProvider interface {
	// Snapshot returns the latest cumulative counter snapshot.
	Snapshot() EBPFSnapshot
}

// Decision is the output of the DecisionEngine for each 100 ms tick.
type Decision struct {
	// PhantomRate is the recommended Phantom injection rate in bytes/s.
	// Range: [0, Config.MaxPhantomBytesS].
	PhantomRate float64
	// SchedulerBias is a dimensionless weight bias for the multipath
	// scheduler in the range [-1, +1].
	// Positive → prefer faster paths; Negative → prefer more reliable paths.
	SchedulerBias float64
	// FECRatio is the FEC redundancy ratio in [0, 1].
	// 0 = no redundancy, 1 = full duplication.
	FECRatio float64
	// BurstMode is true when the link is lightly loaded and short-term
	// bandwidth bursts will not draw DPI attention.
	BurstMode bool
	// TODCoeff is the time-of-day coefficient applied this tick.
	TODCoeff float64
	// UtilFraction is the observed link utilisation in [0, 1] at decision time.
	UtilFraction float64
	// At is when this decision was computed.
	At time.Time
}

// EngineConfig configures the DecisionEngine.
type EngineConfig struct {
	// Governor is the underlying proc/net/dev governor (required).
	Governor *Governor
	// EBPF is the optional eBPF snapshot source.  If nil, only proc metrics
	// are used (fallback mode).
	EBPF SnapshotProvider
	// TickInterval is how often decisions are emitted (default: 100 ms).
	TickInterval time.Duration
	// MaxPhantomBytesS is the ceiling for PhantomRate (default: 512 KiB/s).
	MaxPhantomBytesS float64
	// IATSpikeThreshold is the ratio of current IAT to EWMA IAT that
	// triggers a "spike" — possible DPI probing event (default: 3.0).
	IATSpikeThreshold float64
	// NowFunc is injectable for tests; defaults to time.Now.
	NowFunc func() time.Time
}

func (c *EngineConfig) defaults() {
	if c.TickInterval <= 0 {
		c.TickInterval = 100 * time.Millisecond
	}
	if c.MaxPhantomBytesS == 0 {
		c.MaxPhantomBytesS = 512 * 1024
	}
	if c.IATSpikeThreshold <= 0 {
		c.IATSpikeThreshold = 3.0
	}
	if c.NowFunc == nil {
		c.NowFunc = time.Now
	}
}

// DecisionEngine integrates proc/net/dev throughput and optional eBPF IAT
// telemetry to produce 100 ms adaptive decisions.
type DecisionEngine struct {
	cfg EngineConfig

	mu       sync.RWMutex
	lastDec  *Decision
	iatEWMA  float64 // exponential moving average of IAT in nanoseconds
	prevEBPF EBPFSnapshot
}

// NewDecisionEngine creates a DecisionEngine.  cfg.Governor must be set.
func NewDecisionEngine(cfg EngineConfig) *DecisionEngine {
	cfg.defaults()
	return &DecisionEngine{
		cfg:     cfg,
		iatEWMA: 1e6, // initial EWMA = 1 ms
	}
}

// LastDecision returns the most recently emitted Decision (nil if none yet).
func (e *DecisionEngine) LastDecision() *Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastDec
}

// Run starts the 100 ms decision loop and returns a channel on which Decisions
// are published.  The channel is closed when ctx is cancelled.
// Decisions are non-blocking: if the consumer is slow the previous Decision is
// replaced without blocking the loop.
func (e *DecisionEngine) Run(ctx context.Context) <-chan Decision {
	ch := make(chan Decision, 1)
	go e.loop(ctx, ch)
	return ch
}

const (
	// iatEWMAAlpha is the smoothing factor for the IAT EWMA.
	iatEWMAAlpha = 0.1
	// utilEWMAAlpha is the smoothing factor for link utilisation EWMA.
	utilEWMAAlpha = 0.2
)

func (e *DecisionEngine) loop(ctx context.Context, ch chan Decision) {
	defer close(ch)

	ticker := time.NewTicker(e.cfg.TickInterval)
	defer ticker.Stop()

	var utilEWMA float64 // starts at 0; ramps up naturally

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dec := e.tick(&utilEWMA)

			e.mu.Lock()
			e.lastDec = &dec
			e.mu.Unlock()

			select {
			case ch <- dec:
			default:
				// Consumer slow; drain and replace.
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- dec:
				default:
				}
			}
		}
	}
}

// tick computes one Decision using the latest Governor recommendation and the
// optional eBPF snapshot.
func (e *DecisionEngine) tick(utilEWMA *float64) Decision {
	now := e.cfg.NowFunc()

	// ── 1. proc/net/dev throughput ──────────────────────────────────────
	var tod float64 = 0.5
	var rxBps, maxBps float64

	if rec := e.cfg.Governor.LastRecommendation(); rec != nil {
		tod = rec.TODCoeff
		rxBps = rec.ObservedRxBytesS
		maxBps = e.cfg.Governor.cfg.MaxBandwidthBps
	}

	// Guard against zero maxBps.
	if maxBps <= 0 {
		maxBps = 10 * 1024 * 1024
	}

	utilFrac := rxBps / maxBps
	if utilFrac > 1 {
		utilFrac = 1
	}

	// EWMA-smooth the utilisation.
	*utilEWMA = utilEWMAAlpha*utilFrac + (1-utilEWMAAlpha)*(*utilEWMA)

	// ── 2. eBPF IAT telemetry ────────────────────────────────────────────
	isSpiking := false
	if e.cfg.EBPF != nil {
		snap := e.cfg.EBPF.Snapshot()
		isSpiking = e.updateIAT(snap)
		e.prevEBPF = snap
	}

	// ── 3. Decision logic ────────────────────────────────────────────────
	//
	// PhantomRate:   high when link is idle + no IAT spike; low otherwise.
	// SchedulerBias: positive (fast paths) when utilisation is low.
	// FECRatio:      boosted when IAT spike detected (possible packet loss).
	// BurstMode:     allowed when utilisation EWMA is below 30%.

	phantomBase := e.cfg.MaxPhantomBytesS * tod * (1 - *utilEWMA)
	if isSpiking {
		// Reduce phantom traffic during suspected DPI probing.
		phantomBase *= 0.25
	}
	phantomRate := clamp(phantomBase, 0, e.cfg.MaxPhantomBytesS)

	schedulerBias := clamp(1.0-2.0*(*utilEWMA), -1.0, 1.0)

	fecRatio := 0.05 // baseline 5% redundancy
	if isSpiking {
		fecRatio = 0.25 // boost on suspected probe
	} else if *utilEWMA > 0.7 {
		fecRatio = 0.10 // moderate boost on high utilisation
	}

	burstMode := *utilEWMA < 0.30 && !isSpiking

	return Decision{
		PhantomRate:   phantomRate,
		SchedulerBias: schedulerBias,
		FECRatio:      fecRatio,
		BurstMode:     burstMode,
		TODCoeff:      tod,
		UtilFraction:  *utilEWMA,
		At:            now,
	}
}

// updateIAT updates the IAT EWMA from the latest eBPF snapshot delta and
// returns true when a spike is detected.
//
// We estimate a packet-level IAT from the packet count delta and elapsed time.
// When the estimated IAT is > IATSpikeThreshold × EWMA, we declare a spike.
func (e *DecisionEngine) updateIAT(snap EBPFSnapshot) bool {
	prev := e.prevEBPF

	// Need at least one prior snapshot to compute delta.
	if prev.At.IsZero() {
		return false
	}

	dt := snap.At.Sub(prev.At).Seconds()
	if dt <= 0 {
		return false
	}

	pktDelta := int64(snap.IngressPackets) - int64(prev.IngressPackets)
	if pktDelta <= 0 {
		return false
	}

	// Estimated IAT in nanoseconds: dt_ns / pkt_delta
	dtNs := dt * 1e9
	iatNs := dtNs / float64(pktDelta)

	// Update EWMA.
	e.mu.Lock()
	e.iatEWMA = iatEWMAAlpha*iatNs + (1-iatEWMAAlpha)*e.iatEWMA
	ewma := e.iatEWMA
	e.mu.Unlock()

	// Spike if current estimate is significantly above the EWMA.
	return iatNs > e.cfg.IATSpikeThreshold*ewma
}

// IATEWMANs returns the current IAT EWMA in nanoseconds (for observability).
func (e *DecisionEngine) IATEWMANs() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.iatEWMA
}

// clamp returns v clamped to [lo, hi].
func clamp(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}
