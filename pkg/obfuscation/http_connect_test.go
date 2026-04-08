package obfuscation

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// startFrameEchoServer starts a minimal TCP server that reads length-prefixed
// NABU frames and writes them back verbatim (echo).
// It returns the listen address and a cleanup func.
func startFrameEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go echoFrames(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func echoFrames(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > uint32(transport.MaxPayload+transport.HeaderSize) {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		// Echo: write header then body.
		if _, err := conn.Write(hdr[:]); err != nil {
			return
		}
		if _, err := conn.Write(body); err != nil {
			return
		}
	}
}

// startHTTPConnectProxy starts a minimal HTTP CONNECT proxy for testing.
func startHTTPConnectProxy(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleProxyConn(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func handleProxyConn(client net.Conn) {
	defer client.Close()
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	target, err := net.DialTimeout("tcp", req.Host, 3*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	// Bidirectional copy.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

func TestHTTPConnectDirectNoProxy(t *testing.T) {
	addr, cleanup := startFrameEchoServer(t)
	defer cleanup()

	h, err := NewHTTPConnect(addr, "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}
	h.ReadTimeout = 2 * time.Second
	h.WriteTimeout = 2 * time.Second

	if err := h.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer h.Close()

	want := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 7,
		Seq:      42,
		Payload:  []byte("hello nabu"),
	}
	if err := h.SendFrame(want); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	got, err := h.ReceiveFrame()
	if err != nil {
		t.Fatalf("ReceiveFrame: %v", err)
	}
	if got.StreamID != want.StreamID || got.Seq != want.Seq || string(got.Payload) != string(want.Payload) {
		t.Errorf("echo mismatch: got %+v want %+v", got, want)
	}
}

func TestHTTPConnectMultipleFrames(t *testing.T) {
	addr, cleanup := startFrameEchoServer(t)
	defer cleanup()

	h, err := NewHTTPConnect(addr, "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}
	h.ReadTimeout = 2 * time.Second
	h.WriteTimeout = 2 * time.Second
	if err := h.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer h.Close()

	for i := uint32(1); i <= 5; i++ {
		f := transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagData,
			StreamID: 1,
			Seq:      i,
			Payload:  []byte("frame"),
		}
		if err := h.SendFrame(f); err != nil {
			t.Fatalf("SendFrame %d: %v", i, err)
		}
		got, err := h.ReceiveFrame()
		if err != nil {
			t.Fatalf("ReceiveFrame %d: %v", i, err)
		}
		if got.Seq != i {
			t.Errorf("round %d: got seq %d", i, got.Seq)
		}
	}
}

func TestHTTPConnectViaProxy(t *testing.T) {
	echoAddr, echoClean := startFrameEchoServer(t)
	defer echoClean()
	proxyAddr, proxyClean := startHTTPConnectProxy(t)
	defer proxyClean()

	h, err := NewHTTPConnect(echoAddr, proxyAddr)
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}
	h.ReadTimeout = 2 * time.Second
	h.WriteTimeout = 2 * time.Second
	if err := h.Connect(); err != nil {
		t.Fatalf("Connect via proxy: %v", err)
	}
	defer h.Close()

	want := transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 1,
		Seq:      99,
		Payload:  []byte("proxy test"),
	}
	if err := h.SendFrame(want); err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	got, err := h.ReceiveFrame()
	if err != nil {
		t.Fatalf("ReceiveFrame: %v", err)
	}
	if string(got.Payload) != "proxy test" {
		t.Errorf("got payload %q, want %q", got.Payload, "proxy test")
	}
}

func TestHTTPConnectInterfaceAssertions(t *testing.T) {
	h, err := NewHTTPConnect("127.0.0.1:1234", "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}
	// Verify optional interface implementations.
	if _, ok := transport.Layer(h).(transport.ReadTimeoutSetter); !ok {
		t.Error("HTTPConnect must implement ReadTimeoutSetter")
	}
	if _, ok := transport.Layer(h).(transport.SessionKeySetter); !ok {
		t.Error("HTTPConnect must implement SessionKeySetter")
	}
}

func TestHTTPConnectSetReadTimeout(t *testing.T) {
	h, _ := NewHTTPConnect("127.0.0.1:1234", "")
	h.SetReadTimeout(3 * time.Second)
	if h.ReadTimeout != 3*time.Second {
		t.Errorf("ReadTimeout not set: got %v", h.ReadTimeout)
	}
}

func TestHTTPConnectSetSessionKey(t *testing.T) {
	h, _ := NewHTTPConnect("127.0.0.1:1234", "")
	key := make([]byte, 32)
	h.SetSessionKey(key)
	if len(h.SessionKey) != 32 {
		t.Errorf("SessionKey not set")
	}
}

func TestHTTPConnectNotConnectedErrors(t *testing.T) {
	h, _ := NewHTTPConnect("127.0.0.1:1234", "")
	f := transport.Frame{Version: transport.FrameVersion, Flags: transport.FlagData}
	if err := h.SendFrame(f); err == nil {
		t.Error("SendFrame on unconnected transport should fail")
	}
	if _, err := h.ReceiveFrame(); err == nil {
		t.Error("ReceiveFrame on unconnected transport should fail")
	}
}
