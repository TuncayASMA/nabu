package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

func getFreeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet failed: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

func TestClientRelayUDPRoundTripAck(t *testing.T) {
	addr := getFreeUDPAddr(t)

	s, err := relay.NewUDPServer(addr, nil)
	if err != nil {
		t.Fatalf("new udp server failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	// Give server a short moment to bind.
	time.Sleep(120 * time.Millisecond)

	c, err := transport.NewUDPClient(addr)
	if err != nil {
		t.Fatalf("new udp client failed: %v", err)
	}
	c.ReadTimeout = 2 * time.Second
	if err := c.Connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer c.Close()

	in := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 7,
		Seq:      101,
		Payload:  []byte("hello relay"),
	}

	var ack transport.Frame
	for i := 0; i < 3; i++ {
		if err := c.SendFrame(in); err != nil {
			t.Fatalf("send frame failed: %v", err)
		}
		ack, err = c.ReceiveFrame()
		if err == nil {
			break
		}
		if i == 2 {
			t.Fatalf("receive ack failed after retries: %v", err)
		}
	}
	if ack.Flags != transport.FlagACK {
		t.Fatalf("unexpected ack flag: %d", ack.Flags)
	}
	if ack.StreamID != in.StreamID || ack.Ack != in.Seq {
		t.Fatalf("ack mismatch: got stream=%d ack=%d want stream=%d ack=%d", ack.StreamID, ack.Ack, in.StreamID, in.Seq)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server stop failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop in time")
	}
}
