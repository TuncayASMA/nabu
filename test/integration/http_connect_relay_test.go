package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/obfuscation"
	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/socks5"
	"github.com/TuncayASMA/nabu/pkg/transport"
	"github.com/TuncayASMA/nabu/pkg/tunnel"
)

// startTCPRelayServer starts a TCPServer on a free port and returns its address.
// Cleanup (cancel + drain) is registered via t.Cleanup.
func startTCPRelayServer(t *testing.T, acceptHTTPConnect bool) string {
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
	srv.AcceptHTTPConnect = acceptHTTPConnect

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	// Give the server time to bind.
	time.Sleep(150 * time.Millisecond)

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Log("warning: tcp relay did not stop within cleanup timeout")
		}
	})
	return addr
}

// TestHTTPConnectRelayDirectEcho verifies that an HTTPConnect layer can send a
// frame through the TCPServer (no HTTP CONNECT proxy, AcceptHTTPConnect=false)
// and receive it echoed back through the relay → echo target → client path.
//
// Flow: HTTPConnect.SendFrame → TCPServer → echo TCP server → TCPServer → HTTPConnect.ReceiveFrame
func TestHTTPConnectRelayDirectEcho(t *testing.T) {
	echoAddr, echoStop := startTCPEchoServer(t)

	// Start TCP relay with AcceptHTTPConnect=false (raw TCP frames, no CONNECT preamble).
	relayAddr := startTCPRelayServer(t, false)

	h, err := obfuscation.NewHTTPConnect(relayAddr, "")
	if err != nil {
		echoStop()
		t.Fatalf("NewHTTPConnect: %v", err)
	}
	if err := h.Connect(); err != nil {
		echoStop()
		t.Fatalf("Connect: %v", err)
	}

	// Send a CONNECT frame to the relay's TCP listener.
	connectFrame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: 1,
		Seq:      0,
		Payload:  []byte(echoAddr),
	}
	if err := h.SendFrame(connectFrame); err != nil {
		h.Close()
		echoStop()
		t.Fatalf("SendFrame(CONNECT): %v", err)
	}

	// Expect ACK from relay.
	h.SetReadTimeout(3 * time.Second)
	ack, err := h.ReceiveFrame()
	if err != nil {
		h.Close()
		echoStop()
		t.Fatalf("ReceiveFrame(ACK): %v", err)
	}
	if ack.Flags&transport.FlagACK == 0 {
		h.Close()
		echoStop()
		t.Fatalf("expected ACK, got flags=%02x", ack.Flags)
	}

	// Send DATA frame; expect ACK and then echoed DATA back from relay.
	// The relay may send ACK and DATA in either order, so collect both frames.
	payload := []byte("hello tcp relay")
	dataFrame := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 1,
		Seq:      1,
		Payload:  payload,
	}
	if err := h.SendFrame(dataFrame); err != nil {
		h.Close()
		echoStop()
		t.Fatalf("SendFrame(DATA): %v", err)
	}

	// Read up to 3 frames: we need at least one ACK and one DATA (echo).
	var gotACK, gotData bool
	var echoPayload []byte
	for i := 0; i < 3 && !(gotACK && gotData); i++ {
		h.SetReadTimeout(3 * time.Second)
		f, err := h.ReceiveFrame()
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
		h.Close()
		echoStop()
		t.Fatalf("did not receive ACK for DATA frame")
	}
	if !gotData {
		h.Close()
		echoStop()
		t.Fatalf("did not receive echoed DATA frame from relay")
	}
	if string(echoPayload) != string(payload) {
		h.Close()
		echoStop()
		t.Fatalf("echo mismatch: got %q, want %q", echoPayload, payload)
	}

	// Close HTTPConnect before cleanup; this causes pipeTargetToClient goroutine
	// inside TCPServer to unblock (target read will fail on closed conn).
	h.Close()
	time.Sleep(100 * time.Millisecond)
	echoStop()
}

// TestHTTPConnectViaTCPRelaySOCKS5 tests the full SOCKS5 → HTTPConnect → TCPServer
// → echo server round trip. This exercises tunnel.NewRelayHandlerWithFactory.
func TestHTTPConnectViaTCPRelaySOCKS5(t *testing.T) {
	echoAddr, echoStop := startTCPEchoServer(t)

	// TCP relay with HTTP-CONNECT preamble disabled (raw TCP frames).
	relayAddr := startTCPRelayServer(t, false)

	// Allocate a free TCP port for the SOCKS5 server.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	socksAddr := socksLn.Addr().String()
	_ = socksLn.Close()

	// Build HTTPConnect layer pre-connected to the relay.
	// Use NewRelayHandlerWithFactory so each SOCKS5 session gets its own TCP connection.
	srv := socks5.NewServer(socksAddr)
	srv.OnConnect = tunnel.NewRelayHandlerWithFactory(nil, func() (transport.Layer, error) {
		return obfuscation.NewLayer(obfuscation.ModeHTTPConnect, relayAddr, "")
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.ListenAndServeContext(ctx) }()
	time.Sleep(150 * time.Millisecond)

	// Connect through SOCKS5 to the echo server.
	conn, err := dialSOCKS5(socksAddr, echoAddr)
	if err != nil {
		cancel()
		echoStop()
		t.Fatalf("dialSOCKS5: %v", err)
	}

	want := []byte("obfuscated socks5 path")
	if _, err := conn.Write(want); err != nil {
		conn.Close()
		cancel()
		echoStop()
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := conn.Read(got); err != nil {
		conn.Close()
		cancel()
		echoStop()
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		conn.Close()
		cancel()
		echoStop()
		t.Fatalf("got %q, want %q", got, want)
	}

	// Close connection first so TCPServer pipeTargetToClient goroutine and
	// echo server connection goroutine both unblock before goleak checks.
	conn.Close()
	cancel()
	time.Sleep(200 * time.Millisecond)
	echoStop()
}
