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
	state1.LastSeq = 42
	state1.LastAckTime = time.Now()
	state3 := s.getOrCreateStreamState(1, &addr)
	if state3.LastSeq != 42 {
		t.Errorf("expected LastSeq=42, got %d", state3.LastSeq)
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
