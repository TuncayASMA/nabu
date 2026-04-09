package integration

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

// startProbeDefenseTCPRelay starts a TCPServer with ProbeDefense enabled.
func startProbeDefenseTCPRelay(t *testing.T, pd *relay.ProbeDefense) (string, *relay.TCPServer) {
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
	srv.ProbeDefense = pd

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	time.Sleep(150 * time.Millisecond)

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Log("warning: probe defense tcp relay did not stop")
		}
	})
	return addr, srv
}

// TestProbeDefenseDecoyResponse verifies that an HTTP GET to the relay returns
// a decoy HTML page when ProbeDefense is enabled.
func TestProbeDefenseDecoyResponse(t *testing.T) {
	pd := relay.NewProbeDefense()
	addr, _ := startProbeDefenseTCPRelay(t, pd)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send an HTTP GET request (simulated prober).
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	resp, err := io.ReadAll(conn)
	if err != nil && !isTimeoutOrEOF(err) {
		t.Fatalf("read response: %v", err)
	}

	respStr := string(resp)
	if !strings.Contains(respStr, "HTTP/1.1 200 OK") {
		t.Fatalf("expected 200 OK decoy, got:\n%s", respStr)
	}
	if !strings.Contains(respStr, "nginx/1.24.0") {
		t.Fatalf("expected nginx Server header in decoy, got:\n%s", respStr)
	}
	if !strings.Contains(respStr, "Mehmet Yilmaz") {
		t.Fatalf("expected decoy blog content, got:\n%s", respStr)
	}
}

// TestProbeDefenseAboutPath verifies the /about decoy page is served.
func TestProbeDefenseAboutPath(t *testing.T) {
	pd := relay.NewProbeDefense()
	addr, _ := startProbeDefenseTCPRelay(t, pd)

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET /about HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	resp, _ := io.ReadAll(conn)
	if !strings.Contains(string(resp), "About Me") {
		t.Fatalf("expected /about decoy body, got:\n%s", resp)
	}
}

// TestProbeDefenseBanAfterN verifies that after BanThreshold probes from the
// same IP the server silently drops subsequent connections (no response body).
func TestProbeDefenseBanAfterN(t *testing.T) {
	pd := relay.NewProbeDefense()
	pd.BanThreshold = 3
	pd.BanWindow = time.Minute
	pd.BanDuration = time.Hour

	addr, _ := startProbeDefenseTCPRelay(t, pd)

	sendProbe := func() string {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return ""
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, _ := io.ReadAll(conn)
		return string(data)
	}

	// First BanThreshold probes: each should get a response (either decoy or empty).
	// After the BanThreshold-th probe, the IP is banned.
	for i := 0; i < pd.BanThreshold; i++ {
		sendProbe()
	}

	// Give the server a moment to process ban state.
	time.Sleep(50 * time.Millisecond)

	// Post-ban probe: should be silently dropped (empty response or immediate close).
	resp := sendProbe()
	if strings.Contains(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("expected silent drop for banned IP, but got decoy response: %s", resp[:min(len(resp), 200)])
	}
}

// TestProbeDefenseValidNABUStillWorks verifies that real NABU clients can still
// connect and exchange frames when ProbeDefense is enabled (probe defense must
// NOT block valid non-HTTP connections).
func TestProbeDefenseValidNABUStillWorks(t *testing.T) {
	echoAddr, echoStop := startTCPEchoServer(t)
	t.Cleanup(echoStop)

	pd := relay.NewProbeDefense()
	addr, _ := startProbeDefenseTCPRelay(t, pd)

	// Connect directly to the TCP relay (no HTTP CONNECT / probe defense trigger).
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	// Helper: write a length-prefixed NABU frame.
	writeFrame := func(f transport.Frame) {
		t.Helper()
		encoded, err := transport.EncodeFrame(f)
		if err != nil {
			t.Fatalf("frame encode: %v", err)
		}
		var hdr [4]byte
		hdr[0] = byte(len(encoded) >> 24)
		hdr[1] = byte(len(encoded) >> 16)
		hdr[2] = byte(len(encoded) >> 8)
		hdr[3] = byte(len(encoded))
		_, _ = conn.Write(hdr[:])
		_, _ = conn.Write(encoded)
	}

	// Helper: read a length-prefixed NABU frame.
	rd := bufio.NewReader(conn)
	readFrame := func() transport.Frame {
		t.Helper()
		var hdr [4]byte
		if _, err := io.ReadFull(rd, hdr[:]); err != nil {
			t.Fatalf("read len header: %v", err)
		}
		sz := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		buf := make([]byte, sz)
		if _, err := io.ReadFull(rd, buf); err != nil {
			t.Fatalf("read frame body: %v", err)
		}
		f, err := transport.DecodeFrame(buf)
		if err != nil {
			t.Fatalf("frame decode: %v", err)
		}
		return f
	}

	// CONNECT frame → relay should forward to echoAddr.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: 1,
		Seq:      0,
		Payload:  []byte(echoAddr),
	})

	ack := readFrame()
	if ack.Flags&transport.FlagACK == 0 {
		t.Fatalf("expected ACK, got flags=0x%02x", ack.Flags)
	}

	// DATA frame round-trip.
	writeFrame(transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 1,
		Seq:      1,
		Payload:  []byte("probe-defense-test"),
	})

	// handleData sends an ACK immediately, then pipeTargetToClient sends the
	// echoed DATA.  Skip ACK frames and wait for the DATA echo.
	var data transport.Frame
	for {
		f := readFrame()
		if f.Flags&transport.FlagData != 0 {
			data = f
			break
		}
		if f.Flags&transport.FlagFIN != 0 {
			t.Fatalf("got FIN before DATA echo (flags=0x%02x)", f.Flags)
		}
		// ACK or other informational frame — keep reading.
	}
	if string(data.Payload) != "probe-defense-test" {
		t.Fatalf("echo mismatch: got %q", data.Payload)
	}
}

func isTimeoutOrEOF(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
