package relay

import (
	"fmt"
	"sync/atomic"
)

// GlobalStats holds server-wide traffic counters.
// All operations use atomic instructions and are safe for concurrent use from
// multiple goroutines without additional locking.
type GlobalStats struct {
	BytesIn   atomic.Int64 // total payload bytes received from clients (post-decrypt)
	BytesOut  atomic.Int64 // total payload bytes sent to clients (pre-encrypt)
	FramesIn  atomic.Int64 // total frames accepted from clients
	FramesOut atomic.Int64 // total frames sent to clients
	DropsRL   atomic.Int64 // frames dropped by rate limiter
}

// Snapshot returns a point-in-time, non-atomic copy of all counters.
func (g *GlobalStats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		BytesIn:   g.BytesIn.Load(),
		BytesOut:  g.BytesOut.Load(),
		FramesIn:  g.FramesIn.Load(),
		FramesOut: g.FramesOut.Load(),
		DropsRL:   g.DropsRL.Load(),
	}
}

// StatsSnapshot is a read-only, non-atomic view of GlobalStats at a moment in time.
type StatsSnapshot struct {
	BytesIn   int64
	BytesOut  int64
	FramesIn  int64
	FramesOut int64
	DropsRL   int64
}

// String returns a human-readable one-line summary.
func (s StatsSnapshot) String() string {
	return fmt.Sprintf(
		"in=%d B (%d frames) out=%d B (%d frames) drops_rl=%d",
		s.BytesIn, s.FramesIn, s.BytesOut, s.FramesOut, s.DropsRL,
	)
}
