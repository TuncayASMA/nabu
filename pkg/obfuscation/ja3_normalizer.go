// Package obfuscation — JA3/JA4 TLS fingerprint normalization.
//
// JA3 is a standard method for fingerprinting TLS ClientHello messages.
// NABU normalizes its TLS fingerprint to match real Chrome/Firefox browsers so
// that DPI engines cannot distinguish relay connections from ordinary browser
// HTTPS traffic.
//
// JA3 algorithm (Salesforce, 2017):
//
//	hash = MD5( TLSVersion + "," + Ciphers + "," + Extensions + "," +
//	            EllipticCurves + "," + EllipticCurvePointFormats )
//
// Values are hyphen-joined with GREASE values (RFC 8701) excluded.
// The final hash is the lowercase hex MD5 of the comma-joined string.
//
// References:
//   - https://github.com/salesforce/ja3
//   - https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
//   - RFC 8701 — GREASE: Generating Random Extensions And Sustained Extensibility
package obfuscation

import (
	"crypto/md5" //nolint:gosec // JA3 specification mandates MD5
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Profile selects a browser TLS fingerprint profile for JA3 normalization.
type Profile int

const (
	// ProfileChrome mimics Chrome 133 (utls.HelloChrome_Auto).
	ProfileChrome Profile = iota
	// ProfileFirefox mimics Firefox 120 (utls.HelloFirefox_Auto).
	ProfileFirefox
	// ProfileEdge mimics Edge 85 (utls.HelloEdge_Auto).
	ProfileEdge
	// ProfileRandom uses a randomized fingerprint (utls.HelloRandomized).
	ProfileRandom
)

// profileHelloID maps each Profile to the corresponding utls.ClientHelloID.
var profileHelloID = map[Profile]utls.ClientHelloID{
	ProfileChrome:  utls.HelloChrome_Auto,
	ProfileFirefox: utls.HelloFirefox_Auto,
	ProfileEdge:    utls.HelloEdge_Auto,
	ProfileRandom:  utls.HelloRandomized,
}

// ExpectedJA3Hash holds the deterministic, GREASE-stripped JA3 hash for
// profiles whose extension order is stable.  Chrome is excluded because
// utls applies ShuffleChromeTLSExtensions which randomizes the extension
// list on every UTLSIdToSpec call, matching real Chrome anti-fingerprinting
// behavior.  Random fingerprints are also excluded.
//
// These values are derived directly from utls.UTLSIdToSpec at version 1.8.2.
// They must be updated whenever the utls dependency is upgraded.
var ExpectedJA3Hash = map[Profile]string{
	ProfileFirefox: "7fbdc1beb9b27dfb24f94e3a7f2112af",
}

// ExpectedCipherString holds the deterministic, GREASE-stripped cipher-suite
// portion of the JA3 string (hyphen-joined decimal values) for each profile.
// Cipher suite ordering is always deterministic regardless of extension
// shuffling, so Chrome is included here.
//
// Derived from utls v1.8.2: HelloChrome_133, HelloFirefox_120.
var ExpectedCipherString = map[Profile]string{
	ProfileChrome: "4865-4866-4867-49195-49199-49196-49200-" +
		"52393-52392-49171-49172-156-157-47-53",
	ProfileFirefox: "4865-4867-4866-49195-49199-52393-52392-" +
		"49196-49200-49162-49161-49171-49172-156-157-47-53",
}

// ProfileName returns the human-readable name for p.
func ProfileName(p Profile) string {
	switch p {
	case ProfileChrome:
		return "chrome133"
	case ProfileFirefox:
		return "firefox120"
	case ProfileEdge:
		return "edge85"
	case ProfileRandom:
		return "random"
	default:
		return fmt.Sprintf("unknown(%d)", int(p))
	}
}

// ProfileFromName converts a human-readable name (case-insensitive) to a
// Profile.  The accepted names mirror UTLSFingerprintNames so that existing CLI
// flags ("chrome", "firefox", …) can be reused.
func ProfileFromName(name string) (Profile, error) {
	switch strings.ToLower(name) {
	case "chrome", "chrome133":
		return ProfileChrome, nil
	case "firefox", "firefox120":
		return ProfileFirefox, nil
	case "edge", "edge85":
		return ProfileEdge, nil
	case "random", "randomized":
		return ProfileRandom, nil
	default:
		return 0, fmt.Errorf("ja3: unknown profile name %q; valid: chrome, firefox, edge, random", name)
	}
}

// isGREASEValue reports whether v is a GREASE value per RFC 8701.
// GREASE values have the form 0x?A?A where '?' is the same nibble.
// Examples: 0x0A0A, 0x1A1A, …, 0xFAFA.
func isGREASEValue(v uint16) bool {
	return (v&0x0f0f == 0x0a0a) && (v>>8 == v&0xff)
}

// extensionID returns the IANA TLS extension type number for a known
// utls.TLSExtension, plus a boolean indicating whether the extension should be
// included in a JA3 computation.
//
// Excluded (second return = false):
//   - GREASE extensions (UtlsGREASEExtension, GREASEEncryptedClientHelloExtension)
//   - Padding (UtlsPaddingExtension) — variable-length noise
//   - Renegotiation info (RenegotiationInfoExtension) — SCSV handles this
//   - Application-Layer Protocol Settings (ApplicationSettingsExtension*) — not
//     part of the original JA3 spec
//   - GenericExtension — unknown type, omit to avoid non-determinism
func extensionID(ext utls.TLSExtension) (uint16, bool) {
	switch ext.(type) {
	case *utls.SNIExtension:
		return 0, true
	case *utls.StatusRequestExtension:
		return 5, true
	case *utls.SupportedCurvesExtension:
		return 10, true
	case *utls.SupportedPointsExtension:
		return 11, true
	case *utls.SignatureAlgorithmsExtension:
		return 13, true
	case *utls.ALPNExtension:
		return 16, true
	case *utls.SCTExtension:
		return 18, true
	case *utls.ExtendedMasterSecretExtension:
		return 23, true
	case *utls.UtlsCompressCertExtension:
		return 27, true
	case *utls.SessionTicketExtension:
		return 35, true
	case *utls.SupportedVersionsExtension:
		return 43, true
	case *utls.PSKKeyExchangeModesExtension:
		return 45, true
	case *utls.SignatureAlgorithmsCertExtension:
		return 50, true
	case *utls.KeyShareExtension:
		return 51, true
	// Excluded — GREASE
	case *utls.UtlsGREASEExtension, *utls.GREASEEncryptedClientHelloExtension:
		return 0, false
	// Excluded — variable-length / non-standard
	case *utls.UtlsPaddingExtension:
		return 0, false
	case *utls.RenegotiationInfoExtension:
		return 0, false
	case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
		return 0, false
	case *utls.GenericExtension:
		return 0, false
	default:
		return 0, false
	}
}

// ComputeJA3CipherString returns the cipher-suite portion of the JA3 string
// (hyphen-joined decimal values, GREASE stripped).  Unlike the full JA3 string,
// this value is deterministic even for profiles that shuffle extension order
// (e.g. Chrome), making it suitable for profile-identity tests.
func ComputeJA3CipherString(spec *utls.ClientHelloSpec) string {
	var cs []string
	for _, c := range spec.CipherSuites {
		if isGREASEValue(c) {
			continue
		}
		cs = append(cs, strconv.FormatUint(uint64(c), 10))
	}
	return strings.Join(cs, "-")
}

// ComputeJA3String returns the raw JA3 input string for spec.
// GREASE values are stripped from cipher suites, extensions, and curves so
// that the result is deterministic regardless of GREASE assignment.
//
// Format: "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"
func ComputeJA3String(spec *utls.ClientHelloSpec) string {
	// JA3 always encodes TLS 1.2 (0x0303 = 771) in the version field,
	// regardless of the SupportedVersions extension contents.
	const tlsVer = uint16(771)

	var cs, exts, curves, points []string

	for _, c := range spec.CipherSuites {
		if isGREASEValue(c) {
			continue
		}
		cs = append(cs, strconv.FormatUint(uint64(c), 10))
	}

	for _, ext := range spec.Extensions {
		// Extract elliptic curve and point-format data before the ID lookup.
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			for _, c := range e.Curves {
				if isGREASEValue(uint16(c)) {
					continue
				}
				curves = append(curves, strconv.FormatUint(uint64(c), 10))
			}
		case *utls.SupportedPointsExtension:
			for _, p := range e.SupportedPoints {
				points = append(points, strconv.FormatUint(uint64(p), 10))
			}
		}

		if id, ok := extensionID(ext); ok {
			exts = append(exts, strconv.FormatUint(uint64(id), 10))
		}
	}

	return fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVer,
		strings.Join(cs, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)
}

// ComputeJA3Hash computes the lowercase hex MD5 JA3 fingerprint hash for spec.
// GREASE values are excluded (see ComputeJA3String).
func ComputeJA3Hash(spec *utls.ClientHelloSpec) string {
	raw := ComputeJA3String(spec)
	sum := md5.Sum([]byte(raw)) //nolint:gosec // JA3 mandates MD5
	return hex.EncodeToString(sum[:])
}

// GetProfileSpec returns the utls.ClientHelloSpec for p.
// The returned spec is a value copy; callers may modify it freely.
func GetProfileSpec(p Profile) (*utls.ClientHelloSpec, error) {
	id, ok := profileHelloID[p]
	if !ok {
		return nil, fmt.Errorf("ja3: unknown profile %d", int(p))
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, fmt.Errorf("ja3: UTLSIdToSpec(%v): %w", id, err)
	}
	return &spec, nil
}

// ValidateProfileJA3 verifies that the computed JA3 hash for p matches the
// expected value stored in ExpectedJA3Hash.  Returns nil if the profile is
// unknown or has no expected hash (e.g. ProfileRandom).
func ValidateProfileJA3(p Profile) error {
	expected, ok := ExpectedJA3Hash[p]
	if !ok {
		return nil // no expected hash for this profile — skip validation
	}
	spec, err := GetProfileSpec(p)
	if err != nil {
		return err
	}
	got := ComputeJA3Hash(spec)
	if got != expected {
		return fmt.Errorf(
			"ja3: profile %s fingerprint mismatch: got %s, want %s "+
				"(utls dependency may need updating)",
			ProfileName(p), got, expected,
		)
	}
	return nil
}

// UTLSDialNormalized dials addr using the TLS fingerprint for profile and
// returns the connected net.Conn.  It is a thin wrapper around UTLSDial that
// translates a Profile value into a utls.ClientHelloID.
//
// If dialTimeout is 0, DefaultTCPDialTimeout is used.
func UTLSDialNormalized(
	addr string,
	cfg *utls.Config,
	profile Profile,
	dialTimeout time.Duration,
) (net.Conn, error) {
	id, ok := profileHelloID[profile]
	if !ok {
		return nil, fmt.Errorf("ja3: unknown profile %d", int(profile))
	}
	return UTLSDial(addr, cfg, id, dialTimeout)
}
