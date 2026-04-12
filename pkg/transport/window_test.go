package transport

import (
	"testing"
	"time"
)

func TestPacketSequencing(t *testing.T) {
	r := NewReassembler(8)

	out := r.Push(Packet{Seq: 0, Payload: []byte("a")})
	if len(out) != 1 || string(out[0].Payload) != "a" {
		t.Fatalf("unexpected out for seq0: %+v", out)
	}

	out = r.Push(Packet{Seq: 1, Payload: []byte("b")})
	if len(out) != 1 || string(out[0].Payload) != "b" {
		t.Fatalf("unexpected out for seq1: %+v", out)
	}
}

func TestSlidingWindowReassembly(t *testing.T) {
	r := NewReassembler(8)

	out := r.Push(Packet{Seq: 1, Payload: []byte("b")})
	if len(out) != 0 {
		t.Fatalf("expected no output yet, got %d", len(out))
	}
	out = r.Push(Packet{Seq: 0, Payload: []byte("a")})
	if len(out) != 2 {
		t.Fatalf("expected 2 packets after reassembly, got %d", len(out))
	}
	if string(out[0].Payload) != "a" || string(out[1].Payload) != "b" {
		t.Fatalf("unexpected order: %q %q", out[0].Payload, out[1].Payload)
	}
}

func TestDuplicateDetection(t *testing.T) {
	r := NewReassembler(8)

	if got := r.Push(Packet{Seq: 0, Payload: []byte("a")}); len(got) != 1 {
		t.Fatalf("first packet should pass, got=%d", len(got))
	}
	if got := r.Push(Packet{Seq: 0, Payload: []byte("dup")}); len(got) != 0 {
		t.Fatalf("duplicate should be dropped, got=%d", len(got))
	}
}

func TestRetransmissionTimeout(t *testing.T) {
	now := time.Unix(0, 0)
	w := NewSendWindow(4, func() time.Time { return now })

	w.MarkSent(10)
	w.UpdateRTTEstimator(100 * time.Millisecond)
	now = now.Add(350 * time.Millisecond)

	if !w.ShouldRetransmit(10) {
		t.Fatal("expected retransmit=true after RTO elapsed")
	}
}
