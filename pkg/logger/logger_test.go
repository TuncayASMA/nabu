package logger

import (
	"log/slog"
	"testing"
)

func TestNewReturnsLogger(t *testing.T) {
	l := New(slog.LevelInfo)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNewWithLevelDebug(t *testing.T) {
	l := NewWithLevel("debug")
	if l == nil {
		t.Fatal("expected non-nil logger for debug level")
	}
}

func TestNewWithLevelUnknownDefaultsInfo(t *testing.T) {
	l := NewWithLevel("nonsense")
	if l == nil {
		t.Fatal("expected non-nil logger for unknown level")
	}
}

// TestSensitiveFieldsNotEmpty is a compile-time / logic guard: the sensitive
// key map must not be empty so that redaction is always active.
func TestSensitiveFieldsNotEmpty(t *testing.T) {
	if len(sensitiveKeys) == 0 {
		t.Fatal("sensitiveKeys map must not be empty")
	}
	if !sensitiveKeys["psk"] {
		t.Error("expected 'psk' to be in sensitiveKeys")
	}
	if !sensitiveKeys["key"] {
		t.Error("expected 'key' to be in sensitiveKeys")
	}
}
