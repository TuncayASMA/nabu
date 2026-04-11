package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// testQUICSelfSignedTLS builds an in-memory TLS pair for tests.
func testQUICSelfSignedTLS(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	srv, err := BuildTLSConfig("", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	cli := &tls.Config{ //nolint:gosec
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"nabu/1", "h3"},
	}
	return srv, cli
}

// startTestQUIC starts a QUICServer on a free UDP port and returns its address.
func startTestQUIC(t *testing.T) string {
	t.Helper()
	srvTLS, _ := testQUICSelfSignedTLS(t)
	port := freeUDPPortN(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)

	srv, err := NewQUICServer(addr, srvTLS, nil)
	if err != nil {
		t.Fatalf("NewQUICServer: %v", err)
	}
	srv.AllowPrivateTargets = true

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	time.Sleep(150 * time.Millisecond)
	t.Cleanup(cancel)
	return addr
}

func freeUDPPortN(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeUDPPort listen: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// quicWriteTestFrame writes a length-prefixed NABU frame to w.
func quicWriteTestFrame(t *testing.T, w io.Writer, f transport.Frame) {
	t.Helper()
	raw, err := transport.EncodeFrame(f)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(raw)))
	if _, err := w.Write(append(hdr[:], raw...)); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

// quicReadTestFrame reads a length-prefixed NABU frame from r.
func quicReadTestFrame(t *testing.T, r *bufio.Reader) transport.Frame {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read len header: %v", err)
	}
	sz := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, sz)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	f, err := transport.DecodeFrame(buf)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	return f
}

// TestQUICServerPingPong verifies that Ping/Pong works over QUIC.
func TestQUICServerPingPong(t *testing.T) {
	relayAddr := startTestQUIC(t)
	_, clientTLS := testQUICSelfSignedTLS(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, relayAddr, clientTLS, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "test done") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(stream)

	// Send Ping.
	quicWriteTestFrame(t, stream, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagPing,
		StreamID: 1,
		Seq:      42,
	})
	pong := quicReadTestFrame(t, rd)
	if pong.Flags&transport.FlagPong == 0 {
		t.Fatalf("expected Pong, got flags=0x%02x", pong.Flags)
	}
	if pong.Ack != 42 {
		t.Fatalf("expected Ack=42, got %d", pong.Ack)
	}
}

// TestQUICServerConnectEcho verifies CONNECT+DATA echo through QUICServer.
func TestQUICServerConnectEcho(t *testing.T) {
	// TCP echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	echoAddr := echoLn.Addr().String()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	t.Cleanup(func() { _ = echoLn.Close() })

	relayAddr := startTestQUIC(t)
	_, clientTLS := testQUICSelfSignedTLS(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, relayAddr, clientTLS, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "test done") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(stream)

	// CONNECT frame.
	quicWriteTestFrame(t, stream, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: 1,
		Seq:      0,
		Payload:  []byte(echoAddr),
	})
	ack := quicReadTestFrame(t, rd)
	if ack.Flags&transport.FlagACK == 0 {
		t.Fatalf("expected ACK, got flags=0x%02x", ack.Flags)
	}

	// DATA frame.
	quicWriteTestFrame(t, stream, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 1,
		Seq:      1,
		Payload:  []byte("quic-echo-test"),
	})

	// Wait for DATA echo (skip ACK frames).
	var echo transport.Frame
	for {
		f := quicReadTestFrame(t, rd)
		if f.Flags&transport.FlagData != 0 {
			echo = f
			break
		}
		if f.Flags&transport.FlagFIN != 0 {
			t.Fatalf("got FIN before DATA echo")
		}
	}
	if string(echo.Payload) != "quic-echo-test" {
		t.Fatalf("echo mismatch: got %q", echo.Payload)
	}
}

// TestQUICServerProbeDefenseDecoy verifies that HTTP GET probes receive a
// decoy response when ProbeDefense is enabled.
func TestQUICServerProbeDefenseDecoy(t *testing.T) {
	srvTLS, _ := testQUICSelfSignedTLS(t)
	port := freeUDPPortN(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)

	srv, err := NewQUICServer(addr, srvTLS, nil)
	if err != nil {
		t.Fatalf("NewQUICServer: %v", err)
	}
	srv.AllowPrivateTargets = true
	srv.ProbeDefense = NewProbeDefense()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	time.Sleep(150 * time.Millisecond)
	t.Cleanup(cancel)

	_, clientTLS := testQUICSelfSignedTLS(t)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conn, err := quic.DialAddr(dialCtx, addr, clientTLS, nil)
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "test done") }()

	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))

	_, _ = stream.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
	resp, _ := io.ReadAll(stream)
	if len(resp) == 0 {
		t.Fatal("expected decoy response, got empty")
	}
	respStr := string(resp)
	if len(respStr) > 0 && respStr[:7] != "HTTP/1." {
		t.Fatalf("expected HTTP decoy, got: %q", respStr[:min(len(respStr), 80)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
