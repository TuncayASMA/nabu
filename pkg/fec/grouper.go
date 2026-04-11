package fec

import (
	"context"
	"sync"
	"time"
)

// GroupFlushTimeout is the maximum time a Grouper waits before flushing an
// incomplete group.  This bounds latency at the cost of sub-optimal FEC.
const GroupFlushTimeout = 50 * time.Millisecond

// FECGroup is the output of the Grouper: a set of frames (data + parity) that
// constitute one Reed-Solomon group.
type FECGroup struct {
	GroupID uint32
	Frames  [][]byte // len = Codec.TotalShards()
}

// Grouper batches raw packets into FEC groups via a Codec.
//
// Packets are accumulated until either:
//   - DataShards packets are queued (group full), or
//   - GroupFlushTimeout has elapsed since the oldest queued packet (flush).
//
// The Grouper is safe for concurrent calls to Add.
type Grouper struct {
	codec   *Codec
	ratio   float64 // FECRatio in [0,1]; < 1 / DataShards means bypass
	groupID uint32

	mu      sync.Mutex
	pending [][]byte
	timer   *time.Timer

	outCh chan FECGroup
	once  sync.Once
}

// NewGrouper creates a Grouper backed by codec.
//
// ratio is the FEC redundancy ratio in [0, 1] as produced by DecisionEngine.
// ratio = 0 means bypass FEC (pass-through); ratio = 1 means full parity.
func NewGrouper(codec *Codec, ratio float64) *Grouper {
	return &Grouper{
		codec: codec,
		ratio: clampRatio(ratio),
		outCh: make(chan FECGroup, 64),
	}
}

// SetRatio updates the live FEC ratio.  The change takes effect at the next
// group flush.
func (g *Grouper) SetRatio(ratio float64) {
	g.mu.Lock()
	g.ratio = clampRatio(ratio)
	g.mu.Unlock()
}

// Out returns the channel on which encoded FECGroups are published.
func (g *Grouper) Out() <-chan FECGroup { return g.outCh }

// Add enqueues a raw packet for FEC encoding.  If the group is full it is
// flushed immediately; otherwise a flush timer is armed.
//
// Add must not be called after Close.
func (g *Grouper) Add(pkt []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Take a copy so the caller may reuse the buffer.
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	g.pending = append(g.pending, cp)

	if len(g.pending) >= g.codec.dataShards {
		// Group full — flush synchronously (still under lock).
		g.flushLocked()
		return
	}

	// Arm/reset flush timer.
	if g.timer == nil {
		g.timer = time.AfterFunc(GroupFlushTimeout, g.timerFlush)
	}
}

// timerFlush is the timer callback; runs outside the lock.
func (g *Grouper) timerFlush() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.timer = nil
	if len(g.pending) > 0 {
		g.flushLocked()
	}
}

// flushLocked encodes the pending batch and sends a FECGroup to outCh.
// Must be called with g.mu held.
func (g *Grouper) flushLocked() {
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}

	id := g.groupID
	g.groupID++

	batch := g.pending
	g.pending = nil

	// Release lock before encoding (may allocate).
	g.mu.Unlock()
	frames, err := g.codec.Encode(id, batch)
	g.mu.Lock()

	if err != nil || frames == nil {
		return // drop group on encode error
	}

	fg := FECGroup{GroupID: id, Frames: frames}
	select {
	case g.outCh <- fg:
	default:
		// Consumer not keeping up; drop oldest slot.
		select {
		case <-g.outCh:
		default:
		}
		select {
		case g.outCh <- fg:
		default:
		}
	}
}

// Flush forces an immediate group flush even if fewer than DataShards
// packets are pending.
func (g *Grouper) Flush() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pending) > 0 {
		g.flushLocked()
	}
}

// Close drains the pending batch and closes the Out channel.
func (g *Grouper) Close() {
	g.once.Do(func() {
		g.mu.Lock()
		if g.timer != nil {
			g.timer.Stop()
			g.timer = nil
		}
		if len(g.pending) > 0 {
			g.flushLocked()
		}
		g.mu.Unlock()
		close(g.outCh)
	})
}

// Run starts a background goroutine that drains the Grouper's In channel and
// calls Add for each packet, stopping when ctx is cancelled or inCh is
// closed.  Callers that prefer direct Add calls do not need Run.
func (g *Grouper) Run(ctx context.Context, inCh <-chan []byte) {
	go func() {
		defer g.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-inCh:
				if !ok {
					return
				}
				g.Add(pkt)
			}
		}
	}()
}

// clampRatio clamps r to [0, 1].
func clampRatio(r float64) float64 {
	if r < 0 {
		return 0
	}
	if r > 1 {
		return 1
	}
	return r
}
