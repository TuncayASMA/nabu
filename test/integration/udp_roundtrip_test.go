package integration

import (
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

func TestClientRelayUDPRoundTripAck(t *testing.T) {
	addr := getFreeUDPAddr(t)

	s, err := relay.NewUDPServer(addr, nil)
	if err != nil {
		t.Fatalf("new udp server failed: %v", err)
	}
	s.AllowPrivateTargets = true

	startConfiguredRelay(t, addr, s)

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	c, err := transport.NewUDPClient(addr)
	if err != nil {
		t.Fatalf("new udp client failed: %v", err)
	}
	c.ReadTimeout = 2 * time.Second
	if err := c.Connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer c.Close()

	connectFrame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: 7,
		Seq:      100,
		Payload:  []byte(echoAddr),
	}
	if err := c.SendFrame(connectFrame); err != nil {
		t.Fatalf("send connect frame failed: %v", err)
	}

	connectAck, err := c.ReceiveFrame()
	if err != nil {
		t.Fatalf("receive connect ack failed: %v", err)
	}
	if connectAck.Flags != transport.FlagACK || connectAck.Ack != connectFrame.Seq {
		t.Fatalf("unexpected connect ack: %+v", connectAck)
	}

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
		for j := 0; j < 3; j++ {
			ack, err = c.ReceiveFrame()
			if err != nil {
				break
			}
			if ack.Flags == transport.FlagACK {
				err = nil
				break
			}
		}
		if i == 2 {
			t.Fatalf("receive ack failed after retries: %v", err)
		}
		if err == nil && ack.Flags == transport.FlagACK {
			break
		}
	}
	if ack.Flags != transport.FlagACK {
		t.Fatalf("unexpected ack flag: %d", ack.Flags)
	}
	if ack.StreamID != in.StreamID || ack.Ack != in.Seq {
		t.Fatalf("ack mismatch: got stream=%d ack=%d want stream=%d ack=%d", ack.StreamID, ack.Ack, in.StreamID, in.Seq)
	}

}
