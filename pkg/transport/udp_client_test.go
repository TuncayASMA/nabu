package transport

import (
	"net"
	"testing"
	"time"
)

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

// TestMeasureRTTPingPong starts a minimal UDP echo that replies with FlagPong
// when it receives a FlagPing frame, then verifies MeasureRTT returns a
// positive duration.
func TestMeasureRTTPingPong(t *testing.T) {
	t.Parallel()

	// Start a tiny UDP server that responds to Ping with Pong.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, HeaderSize+MaxPayload)
		for {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			f, decErr := DecodeFrame(buf[:n])
			if decErr != nil {
				continue
			}
			if f.Flags&FlagPing == 0 {
				continue
			}
			pong := Frame{
				Version:  FrameVersion,
				Flags:    FlagPong,
				StreamID: f.StreamID,
				Ack:      f.Seq,
			}
			raw, _ := EncodeFrame(pong)
			pc.WriteTo(raw, addr) //nolint:errcheck
		}
	}()

	client, err := NewUDPClient(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	client.ReadTimeout = 2 * time.Second

	rtt, err := client.MeasureRTT(1, 42)
	if err != nil {
		t.Fatalf("MeasureRTT: %v", err)
	}
	if rtt <= 0 {
		t.Fatalf("expected positive RTT, got %v", rtt)
	}
	t.Logf("loopback RTT = %v", rtt)
}

// TestMeasureRTTTimeout verifies that MeasureRTT returns an error when no Pong arrives.
func TestMeasureRTTTimeout(t *testing.T) {
	t.Parallel()

	// A UDP server that reads but never replies.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	client, err := NewUDPClient(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	client.ReadTimeout = 100 * time.Millisecond // short timeout

	_, err = client.MeasureRTT(1, 7)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	t.Logf("timeout error (expected): %v", err)
}
