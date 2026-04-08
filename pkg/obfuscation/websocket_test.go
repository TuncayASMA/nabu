package obfuscation

import (
	"net"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// ── WS frame encode / decode ─────────────────────────────────────────────────

// TestWSFrameUnmasked verifies that wsWriteFrame (mask=false) produces a frame
// that wsReadFrame decodes back to the original payload.
func TestWSFrameUnmasked(t *testing.T) {
	payload := []byte("hello nabu")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- wsWriteFrame(c1, payload, false)
	}()

	got, err := wsReadFrame(c2)
	if err != nil {
		t.Fatalf("wsReadFrame: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("wsWriteFrame: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
}

// TestWSFrameMasked verifies that client-side masking is correctly applied and
// then stripped by wsReadFrame.
func TestWSFrameMasked(t *testing.T) {
	payload := []byte("masked websocket frame test")
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- wsWriteFrame(c1, payload, true)
	}()

	got, err := wsReadFrame(c2)
	if err != nil {
		t.Fatalf("wsReadFrame: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("wsWriteFrame (masked): %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("masked payload mismatch: got %q want %q", got, payload)
	}
}

// TestWSFrameLargePayload exercises the 16-bit extended length path (len > 125).
func TestWSFrameLargePayload(t *testing.T) {
	payload := make([]byte, 1024) // 1 KiB — uses 16-bit extended length
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- wsWriteFrame(c1, payload, false)
	}()

	got, err := wsReadFrame(c2)
	if err != nil {
		t.Fatalf("wsReadFrame large: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("wsWriteFrame large: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("length mismatch: got %d want %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte mismatch at index %d", i)
		}
	}
}

// ── wsConn (WrapWebSocket) ───────────────────────────────────────────────────

// TestWrapWebSocketRoundTrip verifies that wsConn.Write/Read round-trip a
// message correctly through a net.Pipe().
func TestWrapWebSocketRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wc1 := WrapWebSocket(c1, true /*isClient*/)
	wc2 := WrapWebSocket(c2, false /*isServer*/)

	msg := []byte("round-trip test message")
	errCh := make(chan error, 1)
	go func() {
		_, err := wc1.Write(msg)
		errCh <- err
	}()

	buf := make([]byte, 64)
	n, err := wc2.Read(buf)
	if err != nil {
		t.Fatalf("wsConn.Read: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("wsConn.Write: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("got %q want %q", buf[:n], msg)
	}
}

// ── WebSocket handshake ──────────────────────────────────────────────────────

// TestWSHandshakeClientServer performs a full handshake over a net.Pipe and
// then exchanges one WebSocket binary frame end-to-end.
func TestWSHandshakeClientServer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan error, 1)
	go func() {
		done <- WSServerHandshake(c2)
	}()

	if err := WSClientHandshake(c1, "relay.example.com", "/"); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// After upgrade, both sides should be able to exchange WS frames.
	ping := []byte("ping-after-upgrade")
	go wsWriteFrame(c1, ping, true) //nolint:errcheck

	pong, err := wsReadFrame(c2)
	if err != nil {
		t.Fatalf("post-handshake frame read: %v", err)
	}
	if string(pong) != string(ping) {
		t.Fatalf("frame mismatch after handshake: got %q want %q", pong, ping)
	}
}

// ── WebSocketLayer ───────────────────────────────────────────────────────────

// TestWebSocketLayerSendReceive exercises a full WebSocketLayer round-trip:
// client side → WebSocketLayer.SendFrame → (in-process server) → WebSocketLayer.ReceiveFrame.
func TestWebSocketLayerSendReceive(t *testing.T) {
	// in-process TCP listener acts as a minimal WebSocket relay endpoint.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		// Perform server-side WS upgrade.
		if err := WSServerHandshake(conn); err != nil {
			serverDone <- err
			return
		}
		// Wrap and echo one length-prefixed NABU frame back.
		srv := WrapWebSocket(conn, false /*server*/)
		buf := make([]byte, 65536)
		n, err := srv.Read(buf)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = srv.Write(buf[:n])
		serverDone <- err
	}()

	// Client side.
	layer, err := NewWebSocketLayer(ln.Addr().String())
	if err != nil {
		t.Fatalf("NewWebSocketLayer: %v", err)
	}
	if err := layer.Connect(); err != nil {
		t.Fatalf("layer.Connect: %v", err)
	}
	defer layer.Close()

	sent := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 42,
		Seq:      7,
		Payload:  []byte("hello from websocket layer"),
	}
	if err := layer.SendFrame(sent); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}

	_ = layer.rawConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recv, err := layer.ReceiveFrame()
	if err != nil {
		t.Fatalf("ReceiveFrame: %v", err)
	}

	if recv.StreamID != sent.StreamID || recv.Seq != sent.Seq || string(recv.Payload) != string(sent.Payload) {
		t.Fatalf("frame mismatch: got %+v want %+v", recv, sent)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
