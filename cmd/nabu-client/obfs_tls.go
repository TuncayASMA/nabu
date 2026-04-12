package main

import (
	"crypto/tls"
	"log/slog"

	"github.com/TuncayASMA/nabu/pkg/obfuscation"
	"github.com/TuncayASMA/nabu/pkg/transport"
)

func applyObfsTLSOptions(layer transport.Layer, enabled, insecure, utlsEnabled bool, fingerprint string, log *slog.Logger, obfsMode string) {
	if !enabled || layer == nil {
		return
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecure, //nolint:gosec // opt-in flag
	}

	switch l := layer.(type) {
	case *obfuscation.HTTPConnect:
		l.RelayTLSConfig = tlsCfg
		if utlsEnabled {
			l.UTLSEnabled = true
			l.UTLSFingerprint = fingerprint
		}
		log.Info("relay TLS etkin",
			slog.Bool("insecure", insecure),
			slog.Bool("utls", utlsEnabled),
			slog.String("fingerprint", fingerprint),
		)
	case *obfuscation.WebSocketLayer:
		l.TLSConfig = tlsCfg
		if utlsEnabled {
			l.UTLSEnabled = true
			l.UTLSFingerprint = fingerprint
		}
		log.Info("relay WSS etkin",
			slog.Bool("insecure", insecure),
			slog.Bool("utls", utlsEnabled),
			slog.String("fingerprint", fingerprint),
		)
	default:
		log.Warn("--obfs-tls bu obfuscation modunda desteklenmiyor; göz ardı ediliyor",
			slog.String("mode", obfsMode),
		)
	}
}
