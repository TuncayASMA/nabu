// Package logger provides a production-ready JSON structured logger built on
// top of the standard library log/slog.  It automatically redacts values for
// any attribute key that matches a list of well-known sensitive field names so
// that PSK material, session keys, or passwords never appear in log output.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// sensitiveKeys is the set of slog attribute keys whose values are redacted.
var sensitiveKeys = map[string]bool{
	"psk":          true,
	"key":          true,
	"session_key":  true,
	"password":     true,
	"secret":       true,
	"token":        true,
	"private":      true,
	"private_key":  true,
	"access_token": true,
}

// New returns a JSON slog.Logger that writes to stderr.
// All attributes whose keys match sensitiveKeys are replaced with the literal
// string "***REDACTED***" before the record is written.
func New(level slog.Level) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     level,
		AddSource: false,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if sensitiveKeys[strings.ToLower(a.Key)] {
				return slog.String(a.Key, "***REDACTED***")
			}
			return a
		},
	})
	return slog.New(handler)
}

// NewWithLevel returns a JSON slog.Logger for the named text level.
// Recognised values (case-insensitive): "debug", "info", "warn", "error".
// Unknown values default to "info".
func NewWithLevel(levelStr string) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return New(level)
}
