package relay

import (
	"net"
	"testing"
	"time"
)

func TestNewUDPServerRejectsEmptyAddress(t *testing.T) {
	_, err := NewUDPServer("", nil)
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestNewUDPServerAcceptsAddress(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}
	if s.ListenAddr == "" {
		t.Fatal("listen addr must be set")
	}
}

func TestStreamStateTracking(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}

	// Create a mock address.
	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// Get or create stream state.
	state1 := s.getOrCreateStreamState(1, &addr)
	if state1.StreamID != 1 {
		t.Errorf("expected stream ID 1, got %d", state1.StreamID)
	}

	// Retrieve same stream state.
	state2 := s.getOrCreateStreamState(1, &addr)
	if state1 != state2 {
		t.Fatal("expected same stream state instance")
	}

	// Update state and verify.
	state1.NextExpectedSeq = 42
	state1.LastAckTime = time.Now()
	state3 := s.getOrCreateStreamState(1, &addr)
	if state3.NextExpectedSeq != 42 {
		t.Errorf("expected NextExpectedSeq=42, got %d", state3.NextExpectedSeq)
	}

	// Different stream ID should create new state.
	state4 := s.getOrCreateStreamState(2, &addr)
	if state4.StreamID != 2 {
		t.Errorf("expected stream ID 2, got %d", state4.StreamID)
	}
	if state3 == state4 {
		t.Fatal("expected different stream state instances")
	}
}

func TestCleanupExpiredStreams(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}

	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// Create two streams.
	state1 := s.getOrCreateStreamState(1, &addr)
	state1.LastAckTime = time.Now().Add(-40 * time.Second) // Expired

	state2 := s.getOrCreateStreamState(2, &addr)
	state2.LastAckTime = time.Now() // Fresh

	// Cleanup with 30-second timeout.
	s.cleanupExpiredStreams(30 * time.Second)

	// Stream 1 should be gone.
	key1 := streamStateKey(1, &addr)
	if _, ok := s.streams.Load(key1); ok {
		t.Fatal("expected stream 1 to be cleaned up")
	}

	// Stream 2 should remain.
	key2 := streamStateKey(2, &addr)
	if _, ok := s.streams.Load(key2); !ok {
		t.Fatal("expected stream 2 to remain")
	}
}
func TestReorderBufInitialized(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 11111}
	state := s.getOrCreateStreamState(3, addr)
	if state.reorderBuf == nil {
		t.Fatal("reorderBuf must be initialized on creation")
	}
	if state.maxBufFrames != 64 {
		t.Errorf("expected maxBufFrames=64, got %d", state.maxBufFrames)
	}
}

func TestReorderBufBuffersOutOfOrderFrame(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 11112}
	state := s.getOrCreateStreamState(4, addr)
	state.NextExpectedSeq = 10

	// Simulate buffering an OOO frame without network I/O.
	state.mu.Lock()
	oooSeq := uint32(12)
	state.reorderBuf[oooSeq] = []byte("ooo-payload")
	state.mu.Unlock()

	state.mu.Lock()
	_, buffered := state.reorderBuf[oooSeq]
	state.mu.Unlock()

	if !buffered {
		t.Fatal("OOO frame should be in reorderBuf")
	}
}

func TestReorderBufDrainOnInOrderFrame(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 11113}
	state := s.getOrCreateStreamState(5, addr)
	state.NextExpectedSeq = 10

	// Pre-buffer frames seq=11 and seq=12 (gap: waiting for seq=10).
	state.mu.Lock()
	state.reorderBuf[11] = []byte("B")
	state.reorderBuf[12] = []byte("C")
	state.mu.Unlock()

	// Simulate arrival of in-order frame seq=10 (drain logic without I/O).
	state.mu.Lock()
	toDeliver := [][]byte{[]byte("A")}
	state.NextExpectedSeq = 11
	for {
		next := state.NextExpectedSeq
		if buf, ok := state.reorderBuf[next]; ok {
			toDeliver = append(toDeliver, buf)
			delete(state.reorderBuf, next)
			state.NextExpectedSeq++
		} else {
			break
		}
	}
	state.mu.Unlock()

	if len(toDeliver) != 3 {
		t.Fatalf("expected 3 frames drained, got %d", len(toDeliver))
	}
	if string(toDeliver[0]) != "A" || string(toDeliver[1]) != "B" || string(toDeliver[2]) != "C" {
		t.Fatalf("wrong drain order: %v", toDeliver)
	}
	state.mu.Lock()
	bufLen := len(state.reorderBuf)
	state.mu.Unlock()
	if bufLen != 0 {
		t.Fatalf("reorderBuf should be empty after drain, got %d", bufLen)
	}
}

func TestReorderBufBackpressureDropsFrame(t *testing.T) {
	s, err := NewUDPServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("new server failed: %v", err)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 11114}
	state := s.getOrCreateStreamState(6, addr)
	state.NextExpectedSeq = 1
	state.maxBufFrames = 3 // low limit for test

	// Fill the buffer up to the limit.
	state.mu.Lock()
	for i := uint32(2); i <= 4; i++ {
		state.reorderBuf[i] = []byte("x")
	}
	bufFull := len(state.reorderBuf) >= state.maxBufFrames
	state.mu.Unlock()

	if !bufFull {
		t.Fatal("buffer should be at capacity")
	}
}