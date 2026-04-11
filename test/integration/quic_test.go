package integration

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

	"github.com/TuncayASMA/nabu/pkg/relay"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

// startQUICRelay starts a QUICServer and returns its address.
func startQUICRelay(t *testing.T) string {
	t.Helper()
	srvTLS := buildIntegTLS(t)
	port := freeUDPIntegPort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)

	srv, err := relay.NewQUICServer(addr, srvTLS, nil)
	if err != nil {
		t.Fatalf("NewQUICServer: %v", err)
	}
	srv.AllowPrivateTargets = true

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)
	t.Cleanup(cancel)
	return addr
}

func buildIntegTLS(t *testing.T) *tls.Config {
	t.Helper()
	cfg, err := relay.BuildTLSConfig("", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	return cfg
}

func freeUDPIntegPort(t *testing.T) int {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeUDPIntegPort: %v", err)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	_ = ln.Close()
	return port
}

// quicIntegClientTLS returns a permissive client TLS config for integration tests.
func quicIntegClientTLS() *tls.Config {
	return &tls.Config{ //nolint:gosec
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"nabu/1", "h3"},
	}
}

// quicIntegWriteFrame writes a length-prefixed NABU frame.
func quicIntegWriteFrame(t *testing.T, w io.Writer, f transport.Frame) {
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

// quicIntegReadFrame reads a single length-prefixed NABU frame (no skipping).
func quicIntegReadFrame(t *testing.T, r *bufio.Reader) transport.Frame {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("read hdr: %v", err)
	}
	sz := binary.BigEndian.Uint32(hdr[:])
	buf := make([]byte, sz)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	f, err := transport.DecodeFrame(buf)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	return f
}

// quicIntegReadData reads frames, skipping ACKs, until a DATA frame arrives.
func quicIntegReadData(t *testing.T, r *bufio.Reader) transport.Frame {
	t.Helper()
	for {
		f := quicIntegReadFrame(t, r)
		if f.Flags&transport.FlagData != 0 {
			return f
		}
		if f.Flags&transport.FlagFIN != 0 {
			t.Fatalf("got FIN before DATA echo (flags=0x%02x)", f.Flags)
		}
		// ACK or informational — keep reading.
	}
}

// TestQUICRelayPingPong verifies Ping/Pong round-trip through QUICServer.
func TestQUICRelayPingPong(t *testing.T) {
	relayAddr := startQUICRelay(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, relayAddr, quicIntegClientTLS(), nil)
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

	quicIntegWriteFrame(t, stream, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagPing,
		StreamID: 1,
		Seq:      99,
	})
	pong := quicIntegReadFrame(t, rd)
	if pong.Flags&transport.FlagPong == 0 {
		t.Fatalf("expected Pong, got 0x%02x", pong.Flags)
	}
	if pong.Ack != 99 {
		t.Fatalf("expected Ack=99, got %d", pong.Ack)
	}
}

// TestQUICRelayConnectEcho verifies full CONNECT→DATA echo round-trip.
func TestQUICRelayConnectEcho(t *testing.T) {
	echoAddr, echoStop := startTCPEchoServer(t)
	t.Cleanup(echoStop)

	relayAddr := startQUICRelay(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, relayAddr, quicIntegClientTLS(), nil)
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

	quicIntegWriteFrame(t, stream, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagConnect,
		StreamID: 1,
		Seq:      0,
		Payload:  []byte(echoAddr),
	})
	ack := quicIntegReadFrame(t, rd)
	if ack.Flags&transport.FlagACK == 0 {
		t.Fatalf("expected ACK, got 0x%02x", ack.Flags)
	}

	quicIntegWriteFrame(t, stream, transport.Frame{
		Version:  transport.FrameVersion,
		Flags:    transport.FlagData,
		StreamID: 1,
		Seq:      1,
		Payload:  []byte("quic-integ-test"),
	})

	echo := quicIntegReadData(t, rd)
	if string(echo.Payload) != "quic-integ-test" {
		t.Fatalf("echo mismatch: got %q", echo.Payload)
	}
}

// TestQUICRelayMultiStream verifies that two independent QUIC streams on the
// same connection are relayed independently.
func TestQUICRelayMultiStream(t *testing.T) {
	echoAddr, echoStop := startTCPEchoServer(t)
	t.Cleanup(echoStop)

	relayAddr := startQUICRelay(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, relayAddr, quicIntegClientTLS(), &quic.Config{
		MaxIncomingStreams: 256,
	})
	if err != nil {
		t.Fatalf("quic dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "test done") }()

	doStream := func(streamID uint16, payload string) {
		t.Helper()
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("open stream %d: %v", streamID, err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		rd := bufio.NewReader(stream)

		quicIntegWriteFrame(t, stream, transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagConnect,
			StreamID: streamID,
			Seq:      0,
			Payload:  []byte(echoAddr),
		})
		ack := quicIntegReadFrame(t, rd)
		if ack.Flags&transport.FlagACK == 0 {
			t.Fatalf("stream %d: expected ACK, got 0x%02x", streamID, ack.Flags)
		}

		quicIntegWriteFrame(t, stream, transport.Frame{
			Version:  transport.FrameVersion,
			Flags:    transport.FlagData,
			StreamID: streamID,
			Seq:      1,
			Payload:  []byte(payload),
		})

		echo := quicIntegReadData(t, rd)
		if string(echo.Payload) != payload {
			t.Fatalf("stream %d: echo mismatch got %q", streamID, echo.Payload)
		}
	}

	// Run two streams concurrently.
	done := make(chan struct{}, 2)
	go func() { doStream(1, "stream-one-payload"); done <- struct{}{} }()
	go func() { doStream(2, "stream-two-payload"); done <- struct{}{} }()
	<-done
	<-done
}
