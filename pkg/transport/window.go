package transport

import (
	"sync"
	"time"
)

const (
	DefaultWindowSize = 256
	minRTO            = 50 * time.Millisecond
)

// Reassembler keeps in-order delivery with a bounded out-of-order buffer.
type Reassembler struct {
	mu       sync.Mutex
	nextSeq  uint16
	capacity int
	pending  map[uint16]Packet
}

func NewReassembler(capacity int) *Reassembler {
	if capacity <= 0 {
		capacity = DefaultWindowSize
	}
	return &Reassembler{
		capacity: capacity,
		pending:  make(map[uint16]Packet, capacity),
	}
}

// Push inserts one packet and returns newly in-order packets.
func (r *Reassembler) Push(pkt Packet) []Packet {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pkt.Seq < r.nextSeq {
		return nil // old/duplicate
	}
	if pkt.Seq == r.nextSeq {
		out := []Packet{pkt}
		r.nextSeq++
		for {
			next, ok := r.pending[r.nextSeq]
			if !ok {
				break
			}
			out = append(out, next)
			delete(r.pending, r.nextSeq)
			r.nextSeq++
		}
		return out
	}

	if len(r.pending) >= r.capacity {
		return nil // backpressure: drop newest out-of-order frame
	}
	if _, exists := r.pending[pkt.Seq]; exists {
		return nil // duplicate
	}
	r.pending[pkt.Seq] = pkt
	return nil
}

// SendWindow tracks send timestamps and decides retransmissions via RFC6298-like RTO.
type SendWindow struct {
	mu       sync.Mutex
	now      func() time.Time
	sentAt   map[uint16]time.Time
	srtt     time.Duration
	rttvar   time.Duration
	rto      time.Duration
	initedRT bool
}

func NewSendWindow(size int, now func() time.Time) *SendWindow {
	if now == nil {
		now = time.Now
	}
	if size <= 0 {
		size = DefaultWindowSize
	}
	return &SendWindow{
		now:    now,
		sentAt: make(map[uint16]time.Time, size),
		rto:    200 * time.Millisecond,
	}
}

func (w *SendWindow) MarkSent(seq uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sentAt[seq] = w.now()
}

func (w *SendWindow) UpdateRTTEstimator(sample time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if sample <= 0 {
		return
	}
	if !w.initedRT {
		w.srtt = sample
		w.rttvar = sample / 2
		w.initedRT = true
	} else {
		// RFC6298-ish: alpha=1/8, beta=1/4
		err := w.srtt - sample
		if err < 0 {
			err = -err
		}
		w.rttvar = (3*w.rttvar + err) / 4
		w.srtt = (7*w.srtt + sample) / 8
	}
	w.rto = w.srtt + 4*w.rttvar
	if w.rto < minRTO {
		w.rto = minRTO
	}
}

func (w *SendWindow) ShouldRetransmit(seq uint16) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	sent, ok := w.sentAt[seq]
	if !ok {
		return false
	}
	return w.now().Sub(sent) >= w.rto
}
