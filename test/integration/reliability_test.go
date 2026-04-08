package integration

import (
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// dialRelayStream connects to a relay, sends CONNECT, waits for ACK, and returns the client.
func dialRelayStream(t *testing.T, relayAddr, targetAddr string, streamID uint16, connectSeq uint32) *transport.UDPClient {
	t.Helper()
	c, err := transport.NewUDPClient(relayAddr)
	if err != nil {
		t.Fatalf("new udp client failed: %v", err)
	}
	c.ReadTimeout = 2 * time.Second
	if err := c.Connect(); err != nil {
		t.Fatalf("udp connect failed: %v", err)
	}
	if err := c.SendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: streamID,
		Seq:      connectSeq,
		Payload:  []byte(targetAddr),
	}); err != nil {
		t.Fatalf("send connect frame failed: %v", err)
	}
	ack, err := c.ReceiveFrame()
	if err != nil {
		t.Fatalf("receive connect ack failed: %v", err)
	}
	if ack.Flags != transport.FlagACK || ack.Ack != connectSeq {
		t.Fatalf("unexpected connect ack: %+v", ack)
	}
	return c
}

// TestDuplicateDataFrameIsIgnored verifies that sending the same DATA frame twice
// causes the relay to ACK but deliver the payload only once to the target.
func TestDuplicateDataFrameIsIgnored(t *testing.T) {
	relayAddr, cancel, relayErrCh := startRelayServer(t)
	defer func() {
		cancel()
		select {
		case err := <-relayErrCh:
			if err != nil {
				t.Errorf("relay server error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay did not stop in time")
		}
	}()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	const streamID = uint16(20)
	const connectSeq = uint32(200)
	c := dialRelayStream(t, relayAddr, echoAddr, streamID, connectSeq)
	defer c.Close()

	dataFrame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: streamID,
		Seq:      connectSeq + 1,
		Payload:  []byte("hello"),
	}

	// Send same frame twice (simulate retransmit).
	for i := 0; i < 2; i++ {
		if err := c.SendFrame(dataFrame); err != nil {
			t.Fatalf("send data frame %d failed: %v", i+1, err)
		}
	}

	// Drain incoming frames: collect DATA frames (echo) from relay.
	// We expect exactly one echo DATA payload back.
	deadline := time.After(2 * time.Second)
	var received [][]byte
outer:
	for {
		select {
		case <-deadline:
			break outer
		default:
			frame, err := c.ReceiveFrame()
			if err != nil {
				break outer
			}
			if frame.Flags&transport.FlagData != 0 && frame.StreamID == streamID {
				received = append(received, frame.Payload)
			}
		}
	}

	total := 0
	for _, p := range received {
		total += len(p)
	}
	// The echo server returns exactly what it received. If duplicate was delivered
	// to target, total would be 2×len("hello")=10. Expect exactly 5.
	if total != len("hello") {
		t.Fatalf("expected echo of %d bytes, got %d (duplicate delivered?)", len("hello"), total)
	}
}

// TestOutOfOrderDataFrameDeliveredInOrder verifies that sending frames out of order
// (seq n+1 before seq n) results in in-order delivery to the target.
func TestOutOfOrderDataFrameDeliveredInOrder(t *testing.T) {
	relayAddr, cancel, relayErrCh := startRelayServer(t)
	defer func() {
		cancel()
		select {
		case err := <-relayErrCh:
			if err != nil {
				t.Errorf("relay server error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("relay did not stop in time")
		}
	}()

	// Use a custom TCP server that records received bytes in order.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	receivedCh := make(chan []byte, 8)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				receivedCh <- cp
			}
			if err != nil {
				return
			}
		}
	}()

	const streamID = uint16(21)
	const connectSeq = uint32(300)
	c := dialRelayStream(t, relayAddr, ln.Addr().String(), streamID, connectSeq)
	defer c.Close()

	firstSeq := connectSeq + 1
	secondSeq := connectSeq + 2

	// Send second frame first (out of order).
	if err := c.SendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: streamID,
		Seq:      secondSeq,
		Payload:  []byte("B"),
	}); err != nil {
		t.Fatalf("send OOO frame failed: %v", err)
	}

	// Short pause so relay processes OOO frame first.
	time.Sleep(30 * time.Millisecond)

	// Send first frame (triggers drain: delivers "A" then "B").
	if err := c.SendFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: streamID,
		Seq:      firstSeq,
		Payload:  []byte("A"),
	}); err != nil {
		t.Fatalf("send in-order frame failed: %v", err)
	}

	// Collect all bytes delivered to the target within 1.5s.
	deadline := time.After(1500 * time.Millisecond)
	var all []byte
	for {
		select {
		case chunk := <-receivedCh:
			all = append(all, chunk...)
			if string(all) == "AB" {
				return // success
			}
		case <-deadline:
			t.Fatalf("expected target to receive \"AB\" in order, got %q", string(all))
		}
	}
}
