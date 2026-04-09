// Package obfuscation — uTLS dialer for traffic normalisation.
//
// uTLS replaces the standard Go TLS ClientHello with the fingerprint of a
// real browser (Chrome, Firefox, Safari, Edge) so that DPI engines cannot
// distinguish NABU relay connections from ordinary HTTPS browser traffic.
//
// Usage:
//
//	conn, err := UTLSDial("relay.example.com:443", cfg, utls.HelloChrome_Auto)
//
// The returned net.Conn is a fully handshaked TLS connection whose ClientHello
// is byte-for-byte identical to the selected browser fingerprint.
package obfuscation

import (
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// UTLSFingerprintNames maps human-readable names to utls.ClientHelloID values.
// These are the fingerprints accepted by --obfs-utls-fingerprint on nabu-client.
var UTLSFingerprintNames = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"golang":  utls.HelloGolang,     // standard Go TLS — useful for disabling uTLS at runtime
	"random":  utls.HelloRandomized, // randomised fingerprint
}

// ParseUTLSFingerprint converts a name string (case-insensitive) to a
// utls.ClientHelloID.  Returns an error if the name is not recognised.
func ParseUTLSFingerprint(name string) (utls.ClientHelloID, error) {
	id, ok := UTLSFingerprintNames[strings.ToLower(name)]
	if !ok {
		keys := make([]string, 0, len(UTLSFingerprintNames))
		for k := range UTLSFingerprintNames {
			keys = append(keys, k)
		}
		return utls.ClientHelloID{}, fmt.Errorf("unknown uTLS fingerprint %q; valid: %v", name, keys)
	}
	return id, nil
}

// UTLSDial dials addr, wraps the conn with a uTLS ClientHello matching helloID,
// performs the TLS handshake, and returns the resulting net.Conn.
//
// cfg may be nil; in that case sensible defaults are used (no cert checking —
// intended for test/dev). For production, pass a proper *utls.Config.
//
// If helloID is utls.HelloGolang, standard Go TLS is used instead (no uTLS).
func UTLSDial(addr string, cfg *utls.Config, helloID utls.ClientHelloID, dialTimeout time.Duration) (net.Conn, error) {
	if dialTimeout == 0 {
		dialTimeout = DefaultTCPDialTimeout
	}

	d := net.Dialer{Timeout: dialTimeout}
	tcpConn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("utls dial tcp %s: %w", addr, err)
	}

	if cfg == nil {
		cfg = &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test/dev; callers should supply proper cfg
	}

	// Ensure SNI is set from the address when the config doesn't specify it.
	if cfg.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
		}
		cfg = cfg.Clone()
		cfg.ServerName = host
	}

	uconn := utls.UClient(tcpConn, cfg, helloID)
	if err := uconn.Handshake(); err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return uconn, nil
}
