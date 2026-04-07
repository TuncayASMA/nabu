package transport

import "testing"

func TestNewUDPClientRejectsEmptyAddress(t *testing.T) {
	_, err := NewUDPClient("")
	if err == nil {
		t.Fatal("expected error for empty relay address")
	}
}

func TestUDPClientRequiresConnectBeforeIO(t *testing.T) {
	c, err := NewUDPClient("127.0.0.1:9999")
	if err != nil {
		t.Fatalf("new client failed: %v", err)
	}

	if err := c.SendFrame(Frame{Version: FrameVersion, Payload: []byte("x")}); err == nil {
		t.Fatal("expected send error when not connected")
	}
	if _, err := c.ReceiveFrame(); err == nil {
		t.Fatal("expected receive error when not connected")
	}
}
