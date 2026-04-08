package relay

import (
	"testing"
)

func TestReplayWindow_FirstFrame(t *testing.T) {
	w := NewReplayWindow()
	if !w.Check(0) {
		t.Fatal("first frame (seq=0) must be accepted")
	}
}

func TestReplayWindow_DuplicateRejected(t *testing.T) {
	w := NewReplayWindow()
	w.Check(5)
	if w.Check(5) {
		t.Fatal("duplicate seq=5 must be rejected")
	}
}

func TestReplayWindow_OldRejected(t *testing.T) {
	w := NewReplayWindow()
	w.Check(100) // advance front to 101
	if w.Check(0) {
		t.Fatal("seq=0 is too old (front=101) and must be rejected")
	}
}

func TestReplayWindow_OutOfOrder_InWindow(t *testing.T) {
	w := NewReplayWindow()
	// Accept highest first.
	if !w.Check(10) {
		t.Fatal("seq=10 must be accepted")
	}
	// Out-of-order within window.
	if !w.Check(5) {
		t.Fatal("seq=5 is within window and must be accepted")
	}
	// Replay of seq=5 must be rejected.
	if w.Check(5) {
		t.Fatal("replay of seq=5 must be rejected")
	}
}

func TestReplayWindow_WindowBoundary(t *testing.T) {
	w := NewReplayWindow()
	w.Check(64) // front = 65
	// seq=1: diff = 65-1 = 64 → at the very edge, should be accepted
	if !w.Check(1) {
		t.Fatal("seq=1 is at the 64-frame boundary and must be accepted (diff==64)")
	}
	// seq=0: diff = 65-0 = 65 → outside window
	if w.Check(0) {
		t.Fatal("seq=0 is outside the 64-frame window and must be rejected")
	}
}

func TestReplayWindow_LargeJump(t *testing.T) {
	w := NewReplayWindow()
	w.Check(10)
	// Jump 200 frames ahead — old bitmap should be discarded.
	if !w.Check(210) {
		t.Fatal("large jump forward must be accepted")
	}
	// seq=10 is now outside the new window.
	if w.Check(10) {
		t.Fatal("seq=10 is now too old and must be rejected")
	}
}

func TestReplayWindow_Sequential(t *testing.T) {
	w := NewReplayWindow()
	for i := uint32(0); i < 200; i++ {
		if !w.Check(i) {
			t.Fatalf("sequential seq=%d must be accepted", i)
		}
	}
	// Replay the whole range — all must be rejected.
	for i := uint32(137); i < 200; i++ { // last 63 still in window
		if w.Check(i) {
			t.Fatalf("replay of seq=%d must be rejected", i)
		}
	}
}

func TestReplayWindow_Reset(t *testing.T) {
	w := NewReplayWindow()
	w.Check(50)
	w.Reset()
	// After reset the window should accept seq=0 again.
	if !w.Check(0) {
		t.Fatal("after Reset, seq=0 must be accepted")
	}
}
