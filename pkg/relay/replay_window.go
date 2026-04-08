package relay

import "sync"

// ReplayWindow implements a 64-frame sliding-window duplicate / replay detector.
//
// The window tracks the highest accepted sequence number ("front") and a 64-bit
// bitmap of frames within the window.  Acceptance rules:
//
//   - seq >= front          → new (advance window, mark bit, return true)
//   - seq in [front-64, front) → within window: accept only if not already seen
//   - seq < front-64        → too old (always rejects)
//
// Thread-safe.
type ReplayWindow struct {
	mu     sync.Mutex
	front  uint32 // next expected seq (highest accepted + 1)
	bitmap uint64 // bit i is set = seq (front-1-i) has been seen
	ready  bool   // false until first frame accepted
}

// NewReplayWindow returns an initialised ReplayWindow.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Check returns true if seq should be accepted (first time seen and not too old),
// and false if the frame should be dropped (replay or too old).
//
// Calling Check with an accepted seq marks it as seen; subsequent calls with
// the same seq will return false.
func (w *ReplayWindow) Check(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.ready {
		// First ever frame: initialise the window.
		w.front = seq + 1
		w.bitmap = 1 // bit 0 → (front-1) == seq
		w.ready = true
		return true
	}

	if seq >= w.front {
		// Advance window.
		advance := seq - w.front + 1 // how many positions to shift
		if advance >= 64 {
			// Jump beyond whole bitmap — reset it entirely.
			w.bitmap = 0
		} else {
			w.bitmap <<= advance
		}
		// Mark the new seq in the freshly-shifted bitmap.
		// After the shift, bit 0 corresponds to (new_front - 1) == seq.
		w.bitmap |= 1
		w.front = seq + 1
		return true
	}

	// seq < w.front
	diff := w.front - seq // 1-based distance from the front
	if diff > 64 {
		// Too old — outside the window.
		return false
	}

	// diff is in [1, 64]; bit index = diff - 1
	bit := uint64(1) << (diff - 1)
	if w.bitmap&bit != 0 {
		// Already seen.
		return false
	}

	// Within window, not yet seen — accept.
	w.bitmap |= bit
	return true
}

// Reset clears the window state; useful when a new session starts on a
// re-used connection.
func (w *ReplayWindow) Reset() {
	w.mu.Lock()
	w.front = 0
	w.bitmap = 0
	w.ready = false
	w.mu.Unlock()
}
