package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/obfuscation"
	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

// startWSRelayServer starts a TCPServer with AcceptWebSocket=true on a free port.
func startWSRelayServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free TCP port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srv, err := relay.NewTCPServer(addr, nil)
	if err != nil {
		t.Fatalf("NewTCPServer: %v", err)
	}
	srv.AllowPrivateTargets = true
	srv.AcceptWebSocket = true

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	time.Sleep(150 * time.Millisecond)

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Log("warning: ws relay did not stop within cleanup timeout")
		}
	})
	return addr
}

// TestWebSocketRelayDirectEcho verifies that a WebSocketLayer can send a frame
// through the TCPServer (AcceptWebSocket=true) and receive it echoed back.
//
// Flow: WebSocketLayer.SendFrame(CONNECT) → relay dials echo TCP server
//
//	WebSocketLayer.SendFrame(DATA) → relay forwards → echo returns
//	WebSocketLayer.ReceiveFrame() == echoed DATA
func TestWebSocketRelayDirectEcho(t *testing.T) {
	echoAddr, echoStop := startTCPEchoServer(t)

	relayAddr := startWSRelayServer(t)

	layer, err := obfuscation.NewWebSocketLayer(relayAddr)
	if err != nil {
		echoStop()
		t.Fatalf("NewWebSocketLayer: %v", err)
	}
	if err := layer.Connect(); err != nil {
		echoStop()
		t.Fatalf("layer.Connect: %v", err)
	}

	// ── CONNECT frame ──────────────────────────────────────────────────────
	connectFrame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: 1,
		Seq:      0,
		Payload:  []byte(echoAddr),
	}
	if err := layer.SendFrame(connectFrame); err != nil {
		layer.Close()
		echoStop()
		t.Fatalf("SendFrame(CONNECT): %v", err)
	}

	// Expect ACK from relay.
	layer.SetReadTimeout(3 * time.Second)
	ack, err := layer.ReceiveFrame()
	if err != nil {
		layer.Close()
		echoStop()
		t.Fatalf("ReceiveFrame(ACK): %v", err)
	}
	if ack.Flags&transport.FlagACK == 0 {
		layer.Close()
		echoStop()
		t.Fatalf("expected ACK, got flags=0x%02x", ack.Flags)
	}

	// ── DATA frame ─────────────────────────────────────────────────────────
	payload := []byte("hello websocket relay")
	dataFrame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 1,
		Seq:      1,
		Payload:  payload,
	}
	if err := layer.SendFrame(dataFrame); err != nil {
		layer.Close()
		echoStop()
		t.Fatalf("SendFrame(DATA): %v", err)
	}

	// Collect up to 3 frames: expect ACK and DATA (echo) in either order.
	var gotACK, gotData bool
	var echoPayload []byte
	for i := 0; i < 3 && !(gotACK && gotData); i++ {
		layer.SetReadTimeout(3 * time.Second)
		f, err := layer.ReceiveFrame()
		if err != nil {
			break
		}
		if f.Flags&transport.FlagACK != 0 {
			gotACK = true
		}
		if f.Flags&transport.FlagData != 0 {
			gotData = true
			echoPayload = f.Payload
		}
	}
	if !gotACK {
		layer.Close()
		echoStop()
		t.Fatalf("did not receive ACK for DATA frame")
	}
	if !gotData {
		layer.Close()
		echoStop()
		t.Fatalf("did not receive echoed DATA frame from relay")
	}
	if string(echoPayload) != string(payload) {
		layer.Close()
		echoStop()
		t.Fatalf("echo mismatch: got %q, want %q", echoPayload, payload)
	}

	layer.Close()
	time.Sleep(100 * time.Millisecond)
	echoStop()
}
