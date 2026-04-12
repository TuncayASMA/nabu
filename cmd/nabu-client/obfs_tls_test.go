package main

import (
	"crypto/tls"
	"io"
	"log/slog"
	"testing"

	"github.com/TuncayASMA/nabu/pkg/obfuscation"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

type dummyLayer struct{}

func (d *dummyLayer) SendFrame(transport.Frame) error { return nil }
func (d *dummyLayer) ReceiveFrame() (transport.Frame, error) {
	return transport.Frame{}, nil
}
func (d *dummyLayer) Close() error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestApplyObfsTLSOptions_HTTPConnect(t *testing.T) {
	h, err := obfuscation.NewHTTPConnect("127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}

	applyObfsTLSOptions(h, true, true, true, "firefox", testLogger(), obfuscation.ModeHTTPConnect)

	if h.RelayTLSConfig == nil {
		t.Fatal("RelayTLSConfig should be set")
	}
	if h.RelayTLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion mismatch: got=%d want=%d", h.RelayTLSConfig.MinVersion, tls.VersionTLS13)
	}
	if !h.RelayTLSConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should follow flag")
	}
	if !h.UTLSEnabled {
		t.Fatal("UTLSEnabled should be true")
	}
	if h.UTLSFingerprint != "firefox" {
		t.Fatalf("UTLSFingerprint mismatch: got=%q", h.UTLSFingerprint)
	}
}

func TestApplyObfsTLSOptions_WebSocket(t *testing.T) {
	w, err := obfuscation.NewWebSocketLayer("127.0.0.1:9999")
	if err != nil {
		t.Fatalf("NewWebSocketLayer: %v", err)
	}

	applyObfsTLSOptions(w, true, false, true, "chrome", testLogger(), obfuscation.ModeWebSocket)

	if w.TLSConfig == nil {
		t.Fatal("TLSConfig should be set")
	}
	if w.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion mismatch: got=%d want=%d", w.TLSConfig.MinVersion, tls.VersionTLS13)
	}
	if w.TLSConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be false")
	}
	if !w.UTLSEnabled {
		t.Fatal("UTLSEnabled should be true")
	}
	if w.UTLSFingerprint != "chrome" {
		t.Fatalf("UTLSFingerprint mismatch: got=%q", w.UTLSFingerprint)
	}
}

func TestApplyObfsTLSOptions_NoopWhenDisabled(t *testing.T) {
	h, err := obfuscation.NewHTTPConnect("127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}

	applyObfsTLSOptions(h, false, true, true, "edge", testLogger(), obfuscation.ModeHTTPConnect)
	if h.RelayTLSConfig != nil {
		t.Fatal("RelayTLSConfig should stay nil when disabled")
	}
	if h.UTLSEnabled {
		t.Fatal("UTLSEnabled should stay false when disabled")
	}
}

func TestApplyObfsTLSOptions_UnsupportedLayer(t *testing.T) {
	d := &dummyLayer{}
	applyObfsTLSOptions(d, true, true, true, "random", testLogger(), "none")
	// no panic = success for unsupported layer path
}

func TestApplyObfsTLSOptions_TLSWithoutUTLS(t *testing.T) {
	h, err := obfuscation.NewHTTPConnect("127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}

	applyObfsTLSOptions(h, true, false, false, "chrome", testLogger(), obfuscation.ModeHTTPConnect)

	if h.RelayTLSConfig == nil {
		t.Fatal("RelayTLSConfig should be set when TLS enabled")
	}
	if h.UTLSEnabled {
		t.Fatal("UTLSEnabled should remain false when utls disabled")
	}
	if h.UTLSFingerprint != "" {
		t.Fatalf("UTLSFingerprint should remain empty, got=%q", h.UTLSFingerprint)
	}
}

func TestApplyObfsTLSOptions_NilLoggerNoPanic(t *testing.T) {
	h, err := obfuscation.NewHTTPConnect("127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}

	applyObfsTLSOptions(h, true, true, true, "chrome", nil, obfuscation.ModeHTTPConnect)
	if h.RelayTLSConfig == nil {
		t.Fatal("RelayTLSConfig should still be applied with nil logger")
	}
}
