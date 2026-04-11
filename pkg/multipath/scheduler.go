package multipath

import (
	"math"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// PathStats — per-path telemetry snapshot
// ---------------------------------------------------------------------------

// PathStats holds the observable metrics for a single network path.
// All durations are nanosecond-resolution; bandwidth is in bytes per second.
type PathStats struct {
	// ID is an opaque handle identifying the path (e.g., ifindex or relay addr).
	ID uint32

	// RTT is the smoothed round-trip time measured for this path.
	RTT time.Duration

	// Bandwidth is the estimated available throughput in bytes/second.
	// Zero means unknown/unestimated.
	Bandwidth uint64

	// LossRate is the fraction of packets lost on this path, in [0.0, 1.0].
	LossRate float64

	// InFlight is the number of bytes currently unacknowledged on this path.
	InFlight uint64

	// Available indicates whether this path is currently usable.
	Available bool
}

// ---------------------------------------------------------------------------
// Scheduler interface
// ---------------------------------------------------------------------------

// Scheduler selects the best path index from a slice of PathStats.
// Implementations must be safe for concurrent use.
type Scheduler interface {
	// SelectPath returns the index into paths of the chosen path.
	// Returns -1 if no path is suitable.
	SelectPath(paths []PathStats) int
}

// ---------------------------------------------------------------------------
// MinRTTScheduler — pick the available path with the lowest RTT
// ---------------------------------------------------------------------------

// MinRTTScheduler is the default scheduler: it selects the available path
// with the smallest smoothed RTT.  On ties the lower-indexed path wins.
//
// The scheduler also tracks an EWMA of each path's RTT so that transient
// spikes do not immediately cause a path switch.
type MinRTTScheduler struct {
	mu   sync.Mutex
	ewma map[uint32]float64 // path ID → EWMA RTT (nanoseconds)

	// Alpha is the EWMA smoothing factor in (0,1].  Default 0.125 (QUIC-RFC §A.2).
	Alpha float64
}

// NewMinRTT returns a MinRTTScheduler with sensible defaults.
func NewMinRTT() *MinRTTScheduler {
	return &MinRTTScheduler{
		ewma:  make(map[uint32]float64),
		Alpha: 0.125,
	}
}

// SelectPath implements Scheduler.
func (s *MinRTTScheduler) SelectPath(paths []PathStats) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update EWMA for each available path.
	for i := range paths {
		if !paths[i].Available {
			continue
		}
		p := &paths[i]
		rttNs := float64(p.RTT.Nanoseconds())
		prev, ok := s.ewma[p.ID]
		if !ok {
			s.ewma[p.ID] = rttNs
		} else {
			s.ewma[p.ID] = prev + s.Alpha*(rttNs-prev)
		}
	}

	best := -1
	var bestRTT float64
	for i := range paths {
		if !paths[i].Available {
			continue
		}
		r := s.ewma[paths[i].ID]
		if best < 0 || r < bestRTT {
			best = i
			bestRTT = r
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// BLESTScheduler — Blocking Estimation Scheduler
//
// BLEST (Lim & Ott, 2014) picks the path with the lowest estimated Head-of-
// Line blocking risk.  The heuristic penalises paths whose queue depth
// (InFlight / estimated_bandwidth) exceeds a threshold by applying a backoff
// that grows linearly with excess in-flight data.
// ---------------------------------------------------------------------------

const (
	blestAlpha    = 0.125
	blestLambda   = 1.0  // penalty multiplier; raise to be more conservative
	blestMaxQueue = 0.05 // 50 ms queue depth considered acceptable
)

// BLESTScheduler selects the path least likely to cause Head-of-Line blocking.
type BLESTScheduler struct {
	mu   sync.Mutex
	ewma map[uint32]float64 // EWMA RTT per path ID
}

// NewBLEST returns a BLESTScheduler.
func NewBLEST() *BLESTScheduler {
	return &BLESTScheduler{ewma: make(map[uint32]float64)}
}

// SelectPath implements Scheduler.
func (s *BLESTScheduler) SelectPath(paths []PathStats) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update EWMA RTTs.
	for i := range paths {
		if !paths[i].Available {
			continue
		}
		p := &paths[i]
		rttNs := float64(p.RTT.Nanoseconds())
		if prev, ok := s.ewma[p.ID]; !ok {
			s.ewma[p.ID] = rttNs
		} else {
			s.ewma[p.ID] = prev + blestAlpha*(rttNs-prev)
		}
	}

	best := -1
	var bestScore float64
	for i := range paths {
		p := &paths[i]
		if !p.Available {
			continue
		}
		rttSec := s.ewma[p.ID] / float64(time.Second)

		// Queue depth estimate: InFlight / bandwidth (seconds in flight).
		// If bandwidth unknown treat queue depth as zero (optimistic).
		var queueDepth float64
		if p.Bandwidth > 0 {
			queueDepth = float64(p.InFlight) / float64(p.Bandwidth)
		}

		// Penalty: if estimated queue > threshold, add linear overshoot term.
		penalty := 0.0
		if queueDepth > blestMaxQueue {
			penalty = blestLambda * (queueDepth - blestMaxQueue)
		}

		// Include loss-adjusted RTT: effective_RTT ≈ raw_RTT / (1 − loss).
		effectiveRTT := rttSec
		if p.LossRate < 1.0 {
			effectiveRTT = rttSec / (1.0 - p.LossRate)
		}

		score := effectiveRTT + penalty

		if best < 0 || score < bestScore {
			best = i
			bestScore = score
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// RedundantScheduler — send on all available paths
//
// For reliability-critical frames (control packets, key exchanges) the caller
// can use RedundantScheduler to get *all* available path indices.  The
// scheduler itself still exposes the Scheduler interface (SelectPath returns
// the best single path), but also provides SelectAllPaths for multi-path copy.
// ---------------------------------------------------------------------------

// RedundantScheduler duplicates traffic across all available paths.
type RedundantScheduler struct {
	// Primary is the tie-break fallback when only one path is to be chosen.
	Primary Scheduler

	// MaxCopies limits how many paths copies are sent on. 0 means no limit.
	MaxCopies int
}

// NewRedundant returns a RedundantScheduler backed by MinRTT for single-path
// tie-breaking.
func NewRedundant(maxCopies int) *RedundantScheduler {
	return &RedundantScheduler{
		Primary:   NewMinRTT(),
		MaxCopies: maxCopies,
	}
}

// SelectPath implements Scheduler.  Returns Primary.SelectPath result.
func (s *RedundantScheduler) SelectPath(paths []PathStats) int {
	return s.Primary.SelectPath(paths)
}

// SelectAllPaths returns indices of all available paths, capped at MaxCopies.
func (s *RedundantScheduler) SelectAllPaths(paths []PathStats) []int {
	out := make([]int, 0, len(paths))
	for i := range paths {
		if paths[i].Available {
			out = append(out, i)
		}
	}
	if s.MaxCopies > 0 && len(out) > s.MaxCopies {
		out = out[:s.MaxCopies]
	}
	return out
}

// ---------------------------------------------------------------------------
// WeightedRRScheduler — weighted round-robin by bandwidth
// ---------------------------------------------------------------------------

// WeightedRRScheduler distributes load proportionally to each path's
// estimated bandwidth.  It uses a deficit counter per-path so that even
// low-bandwidth paths get their share over time.
type WeightedRRScheduler struct {
	mu      sync.Mutex
	deficit map[uint32]float64
}

// NewWeightedRR returns a WeightedRRScheduler.
func NewWeightedRR() *WeightedRRScheduler {
	return &WeightedRRScheduler{deficit: make(map[uint32]float64)}
}

// SelectPath implements Scheduler.
func (s *WeightedRRScheduler) SelectPath(paths []PathStats) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Compute total bandwidth to derive weights.
	var total float64
	for i := range paths {
		if paths[i].Available {
			total += math.Max(float64(paths[i].Bandwidth), 1)
		}
	}
	if total == 0 {
		return -1
	}

	// Credit each path with its weight-normalised bandwidth share.
	for i := range paths {
		if !paths[i].Available {
			continue
		}
		id := paths[i].ID
		weight := math.Max(float64(paths[i].Bandwidth), 1) / total
		s.deficit[id] += weight
	}

	// Pick the path with the highest accumulated credit.
	best := -1
	var bestCredit float64
	for i := range paths {
		if !paths[i].Available {
			continue
		}
		id := paths[i].ID
		if best < 0 || s.deficit[id] > bestCredit {
			best = i
			bestCredit = s.deficit[id]
		}
	}

	// Consume one unit of credit from the chosen path.
	if best >= 0 {
		s.deficit[paths[best].ID] -= 1.0
	}
	return best
}
