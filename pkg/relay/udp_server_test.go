package relay

import "testing"

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
