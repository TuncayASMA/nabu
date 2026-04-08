package obfuscation_test

import (
	"testing"

	"github.com/TuncayASMA/nabu/pkg/obfuscation"
)

func TestNewLayerNone(t *testing.T) {
	layer, err := obfuscation.NewLayer(obfuscation.ModeNone, "127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if layer != nil {
		t.Fatal("expected nil layer for mode=none")
	}
}

func TestNewLayerEmpty(t *testing.T) {
	layer, err := obfuscation.NewLayer("", "127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if layer != nil {
		t.Fatal("expected nil layer for mode=empty")
	}
}

func TestNewLayerUnknown(t *testing.T) {
	_, err := obfuscation.NewLayer("xor-cipher", "127.0.0.1:9999", "")
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestNewLayerHTTPConnectDialFail(t *testing.T) {
	// Nothing listens on port 1, so Connect() must fail.
	_, err := obfuscation.NewLayer(obfuscation.ModeHTTPConnect, "127.0.0.1:1", "")
	if err == nil {
		t.Fatal("expected dial error for unreachable relay")
	}
}
