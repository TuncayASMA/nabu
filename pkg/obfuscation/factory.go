package obfuscation

import (
	"fmt"

	"github.com/TuncayASMA/nabu/pkg/transport"
)

// ModeNone is the default — raw UDP (no obfuscation).
const ModeNone = "none"

// ModeHTTPConnect tunnels NABU frames through an HTTP CONNECT proxy.
const ModeHTTPConnect = "http-connect"

// NewLayer creates a transport.Layer for the requested obfuscation mode.
//
//   - "none"         → nil, nil  (caller should fall back to UDP)
//   - "http-connect" → *HTTPConnect already connected
//
// relayAddr is the TCP relay endpoint ("host:port").
// proxyAddr is the optional HTTP CONNECT proxy ("host:port"); empty means direct TCP.
func NewLayer(mode, relayAddr, proxyAddr string) (transport.Layer, error) {
	switch mode {
	case ModeNone, "":
		return nil, nil
	case ModeHTTPConnect:
		h, err := NewHTTPConnect(relayAddr, proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("http-connect init: %w", err)
		}
		if err := h.Connect(); err != nil {
			return nil, fmt.Errorf("http-connect dial: %w", err)
		}
		return h, nil
	default:
		return nil, fmt.Errorf("unknown obfuscation mode %q (valid: none, http-connect)", mode)
	}
}
