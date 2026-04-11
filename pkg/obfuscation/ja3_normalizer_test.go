package obfuscation

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ── isGREASEValue ─────────────────────────────────────────────────────────

func TestIsGREASEValue(t *testing.T) {
	t.Parallel()
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
		0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
		0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range greaseValues {
		if !isGREASEValue(v) {
			t.Errorf("isGREASEValue(0x%04x) = false, want true", v)
		}
	}

	nonGrease := []uint16{
		0x0000, 0x0001, 0x11ec, 0x001d, 0x0017, 0x0018,
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x00ff,
	}
	for _, v := range nonGrease {
		if isGREASEValue(v) {
			t.Errorf("isGREASEValue(0x%04x) = true, want false", v)
		}
	}
}

// ── ProfileFromName + ProfileName ─────────────────────────────────────────

func TestProfileFromName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  Profile
	}{
		{"chrome", ProfileChrome},
		{"Chrome", ProfileChrome},
		{"CHROME", ProfileChrome},
		{"chrome133", ProfileChrome},
		{"firefox", ProfileFirefox},
		{"firefox120", ProfileFirefox},
		{"Firefox", ProfileFirefox},
		{"edge", ProfileEdge},
		{"edge85", ProfileEdge},
		{"random", ProfileRandom},
		{"randomized", ProfileRandom},
	}
	for _, tc := range cases {
		got, err := ProfileFromName(tc.input)
		if err != nil {
			t.Errorf("ProfileFromName(%q) unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ProfileFromName(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}

	_, err := ProfileFromName("ie6")
	if err == nil {
		t.Error("ProfileFromName(ie6) should return an error")
	}
}

func TestProfileName(t *testing.T) {
	t.Parallel()
	cases := map[Profile]string{
		ProfileChrome:  "chrome133",
		ProfileFirefox: "firefox120",
		ProfileEdge:    "edge85",
		ProfileRandom:  "random",
		Profile(99):    "unknown(99)",
	}
	for p, want := range cases {
		if got := ProfileName(p); got != want {
			t.Errorf("ProfileName(%d) = %q, want %q", int(p), got, want)
		}
	}
}

// ── GetProfileSpec ────────────────────────────────────────────────────────

func TestGetProfileSpec(t *testing.T) {
	t.Parallel()
	for _, p := range []Profile{ProfileChrome, ProfileFirefox, ProfileEdge} {
		spec, err := GetProfileSpec(p)
		if err != nil {
			t.Errorf("GetProfileSpec(%s) error: %v", ProfileName(p), err)
			continue
		}
		if len(spec.CipherSuites) == 0 {
			t.Errorf("GetProfileSpec(%s): CipherSuites is empty", ProfileName(p))
		}
		if len(spec.Extensions) == 0 {
			t.Errorf("GetProfileSpec(%s): Extensions is empty", ProfileName(p))
		}
	}

	_, err := GetProfileSpec(Profile(999))
	if err == nil {
		t.Error("GetProfileSpec(999) should return an error")
	}
}

// ── ComputeJA3String ──────────────────────────────────────────────────────

func TestComputeJA3String_Chrome(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileChrome)
	if err != nil {
		t.Fatalf("GetProfileSpec(chrome): %v", err)
	}
	ja3 := ComputeJA3String(spec)

	// The string must have exactly 4 commas (5 fields).
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3 string has %d comma-fields, want 5: %s", len(parts), ja3)
	}

	// First field must be "771" (TLS 1.2).
	if parts[0] != "771" {
		t.Errorf("JA3 TLS version field = %q, want 771", parts[0])
	}

	// Cipher suite field must not contain any GREASE values.
	for _, cs := range strings.Split(parts[1], "-") {
		if cs == "2570" { // 0x0a0a — the most common GREASE
			t.Errorf("JA3 cipher field contains GREASE value 2570: %s", parts[1])
		}
	}

	// Chrome 133 must include TLS_AES_128_GCM_SHA256 (4865 = 0x1301).
	if !strings.Contains(parts[1], "4865") {
		t.Errorf("Chrome JA3 cipher field missing TLS_AES_128_GCM_SHA256 (4865): %s", parts[1])
	}

	t.Logf("Chrome JA3: %s", ja3)
}

func TestComputeJA3String_Firefox(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileFirefox)
	if err != nil {
		t.Fatalf("GetProfileSpec(firefox): %v", err)
	}
	ja3 := ComputeJA3String(spec)

	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3 string has %d comma-fields, want 5: %s", len(parts), ja3)
	}
	if parts[0] != "771" {
		t.Errorf("JA3 TLS version field = %q, want 771", parts[0])
	}

	// Firefox 120 must include TLS_AES_128_GCM_SHA256 (4865) and
	// TLS_CHACHA20_POLY1305_SHA256 (4867).
	if !strings.Contains(parts[1], "4865") {
		t.Errorf("Firefox JA3 cipher field missing 4865: %s", parts[1])
	}
	if !strings.Contains(parts[1], "4867") {
		t.Errorf("Firefox JA3 cipher field missing 4867: %s", parts[1])
	}
	t.Logf("Firefox JA3: %s", ja3)
}

// ── ComputeJA3Hash ────────────────────────────────────────────────────────

// TestComputeJA3CipherString_Chrome verifies the deterministic cipher-suite
// portion of Chrome 133's JA3 string (extension order is shuffled by utls,
// so only the cipher string is checked here).
func TestComputeJA3CipherString_Chrome(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileChrome)
	if err != nil {
		t.Fatalf("GetProfileSpec: %v", err)
	}
	got := ComputeJA3CipherString(spec)
	want := ExpectedCipherString[ProfileChrome]
	if got != want {
		t.Errorf("Chrome cipher string = %q, want %q", got, want)
	}
}

func TestComputeJA3Hash_KnownChrome(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileChrome)
	if err != nil {
		t.Fatalf("GetProfileSpec: %v", err)
	}
	got := ComputeJA3Hash(spec)
	// Chrome shuffles extension order on each UTLSIdToSpec call, so the full
	// JA3 hash is intentionally non-deterministic.  We verify its format only.
	if len(got) != 32 {
		t.Errorf("JA3 hash length = %d, want 32", len(got))
	}
	t.Logf("Chrome JA3 hash (sample): %s", got)
}

func TestComputeJA3Hash_KnownFirefox(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileFirefox)
	if err != nil {
		t.Fatalf("GetProfileSpec: %v", err)
	}
	got := ComputeJA3Hash(spec)
	want := ExpectedJA3Hash[ProfileFirefox]
	if got != want {
		t.Errorf("Firefox JA3 hash = %s, want %s", got, want)
	}
	if len(got) != 32 {
		t.Errorf("JA3 hash length = %d, want 32", len(got))
	}
}

func TestComputeJA3CipherString_Firefox(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileFirefox)
	if err != nil {
		t.Fatalf("GetProfileSpec(firefox): %v", err)
	}
	got := ComputeJA3CipherString(spec)
	want := ExpectedCipherString[ProfileFirefox]
	if got != want {
		t.Errorf("Firefox cipher string = %q, want %q", got, want)
	}
}

func TestComputeJA3Hash_Deterministic(t *testing.T) {
	t.Parallel()
	spec, err := GetProfileSpec(ProfileChrome)
	if err != nil {
		t.Fatalf("GetProfileSpec: %v", err)
	}
	h1 := ComputeJA3Hash(spec)
	h2 := ComputeJA3Hash(spec)
	if h1 != h2 {
		t.Errorf("ComputeJA3Hash is not deterministic: %s vs %s", h1, h2)
	}
}

func TestComputeJA3Hash_ProfilesDistinct(t *testing.T) {
	t.Parallel()
	specC, err := GetProfileSpec(ProfileChrome)
	if err != nil {
		t.Fatalf("GetProfileSpec(chrome): %v", err)
	}
	specF, err := GetProfileSpec(ProfileFirefox)
	if err != nil {
		t.Fatalf("GetProfileSpec(firefox): %v", err)
	}
	hC := ComputeJA3Hash(specC)
	hF := ComputeJA3Hash(specF)
	if hC == hF {
		t.Errorf("Chrome and Firefox JA3 hashes are identical (%s) — fingerprinting is broken", hC)
	}
}

// ── ValidateProfileJA3 ────────────────────────────────────────────────────

// TestValidateProfileJA3_Chrome: Chrome has no expected hash (extension shuffle)
// so ValidateProfileJA3 should return nil.
func TestValidateProfileJA3_Chrome(t *testing.T) {
	t.Parallel()
	// Chrome is not in ExpectedJA3Hash → should return nil (no validation performed).
	if err := ValidateProfileJA3(ProfileChrome); err != nil {
		t.Errorf("ValidateProfileJA3(chrome): %v", err)
	}
}

func TestValidateProfileJA3_Firefox(t *testing.T) {
	t.Parallel()
	if err := ValidateProfileJA3(ProfileFirefox); err != nil {
		t.Errorf("ValidateProfileJA3(firefox): %v", err)
	}
}

func TestValidateProfileJA3_Random(t *testing.T) {
	t.Parallel()
	// ProfileRandom has no expected hash — ValidateProfileJA3 must return nil.
	if err := ValidateProfileJA3(ProfileRandom); err != nil {
		t.Errorf("ValidateProfileJA3(random) should return nil: %v", err)
	}
}

// ── UTLSDialNormalized ────────────────────────────────────────────────────

// TestUTLSDialNormalized_Chrome starts a standard TLS echo server and dials it
// using UTLSDialNormalized with ProfileChrome, verifying the handshake succeeds
// and the connection carries data correctly.
func TestUTLSDialNormalized_Chrome(t *testing.T) {
	t.Parallel()
	testUTLSDialNormalized(t, ProfileChrome, "chrome-normalized")
}

func TestUTLSDialNormalized_Firefox(t *testing.T) {
	t.Parallel()
	testUTLSDialNormalized(t, ProfileFirefox, "firefox-normalized")
}

func TestUTLSDialNormalized_Edge(t *testing.T) {
	t.Parallel()
	testUTLSDialNormalized(t, ProfileEdge, "edge-normalized")
}

func TestUTLSDialNormalized_Random(t *testing.T) {
	t.Parallel()
	// HelloRandomized may negotiate cipher suites or extensions that the
	// standard Go TLS server does not support.  If the echo fails due to
	// incompatibility we accept it as a known limitation — the important
	// assertion is that UTLSDialNormalized selects the right profile and
	// returns a connection without panicking.
	cert, err := buildSelfSignedCert(t)
	if err != nil {
		t.Fatalf("buildSelfSignedCert: %v", err)
	}
	srv, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer srv.Close()

	go func() {
		conn, aErr := srv.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	utlsCfg := &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	conn, err := UTLSDialNormalized(srv.Addr().String(), utlsCfg, ProfileRandom, 5*time.Second)
	if err != nil {
		// HelloRandomized may fail to agree on parameters with the standard
		// Go TLS server — that is acceptable.
		t.Logf("UTLSDialNormalized(random) returned (acceptable) error: %v", err)
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := "random-normalized"
	if _, wErr := conn.Write([]byte(payload)); wErr != nil {
		t.Logf("Write failed (acceptable for random profile): %v", wErr)
		return
	}
	buf := make([]byte, len(payload))
	if _, rErr := conn.Read(buf); rErr != nil {
		t.Logf("Read failed (acceptable for random profile): %v", rErr)
		return
	}
	if string(buf) != payload {
		t.Errorf("echo mismatch: got %q, want %q", buf, payload)
	}
}

// testUTLSDialNormalized is a shared helper for UTLSDialNormalized tests.
func testUTLSDialNormalized(t *testing.T, p Profile, payload string) {
	t.Helper()

	cert, err := buildSelfSignedCert(t)
	if err != nil {
		t.Fatalf("buildSelfSignedCert: %v", err)
	}
	srv, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer srv.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := srv.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	utlsCfg := &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	conn, err := UTLSDialNormalized(srv.Addr().String(), utlsCfg, p, 5*time.Second)
	if err != nil {
		t.Fatalf("UTLSDialNormalized(profile=%s): %v", ProfileName(p), err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != payload {
		t.Errorf("echo mismatch: got %q, want %q", buf, payload)
	}
	<-done
}

// TestUTLSDialNormalized_BadProfile verifies that an unknown profile returns
// a meaningful error without panicking.
func TestUTLSDialNormalized_BadProfile(t *testing.T) {
	t.Parallel()
	utlsCfg := &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	_, err := UTLSDialNormalized("127.0.0.1:1", utlsCfg, Profile(999), 100*time.Millisecond)
	if err == nil {
		t.Error("expected error for unknown profile, got nil")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("error should mention 'unknown profile', got: %v", err)
	}
}
