package obfuscation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestParseUTLSFingerprint verifies that all documented fingerprint names are
// parsed successfully and that an unknown name returns an error.
func TestParseUTLSFingerprint(t *testing.T) {
	t.Parallel()
	valid := []string{"chrome", "firefox", "safari", "edge", "golang", "random",
		"Chrome", "FIREFOX"} // case-insensitive
	for _, name := range valid {
		id, err := ParseUTLSFingerprint(name)
		if err != nil {
			t.Errorf("ParseUTLSFingerprint(%q) returned unexpected error: %v", name, err)
		}
		if id == (utls.ClientHelloID{}) {
			t.Errorf("ParseUTLSFingerprint(%q) returned zero ClientHelloID", name)
		}
	}

	_, err := ParseUTLSFingerprint("unknown-browser")
	if err == nil {
		t.Error("ParseUTLSFingerprint(unknown) should have returned an error")
	}
}

// TestUTLSDialChromeFingerprint verifies that UTLSDial connects to a real TLS
// server and returns a working net.Conn using the Chrome fingerprint.
//
// The test sets up a minimal TLS server using the standard library — this is
// intentional: if the server were also using uTLS it might advertise the wrong
// cipher suites.  A standard tls.Server is the best compatibility target.
func TestUTLSDialChromeFingerprint(t *testing.T) {
	t.Parallel()

	// ── Build a self-signed TLS server ──────────────────────────────────────
	cert, err := buildSelfSignedCert(t)
	if err != nil {
		t.Fatalf("buildSelfSignedCert: %v", err)
	}
	srv, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // accept both TLS 1.2 and 1.3
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer srv.Close()

	ready := make(chan struct{})
	echo := make(chan []byte, 1)
	go func() {
		close(ready)
		conn, err := srv.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		echo <- buf[:n]
		_, _ = conn.Write(buf[:n])
	}()
	<-ready

	// ── Dial with uTLS Chrome fingerprint ───────────────────────────────────
	utlsCfg := &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	conn, err := UTLSDial(srv.Addr().String(), utlsCfg, utls.HelloChrome_Auto, 5*time.Second)
	if err != nil {
		t.Fatalf("UTLSDial: %v", err)
	}
	defer conn.Close()

	want := []byte("utls-payload")
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := conn.Read(got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q, want %q", got, want)
	}
}

// TestUTLSDialFirefoxFingerprint verifies the Firefox fingerprint path.
func TestUTLSDialFirefoxFingerprint(t *testing.T) {
	t.Parallel()

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
		conn, err := srv.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	utlsCfg := &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	conn, err := UTLSDial(srv.Addr().String(), utlsCfg, utls.HelloFirefox_Auto, 5*time.Second)
	if err != nil {
		t.Fatalf("UTLSDial(firefox): %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("ff"))
	buf := make([]byte, 2)
	_, _ = conn.Read(buf)
}

// TestUTLSDialUnknownHost verifies that UTLSDial returns a meaningful error
// when the host is unreachable (fast timeout via 0.0.0.0:1).
func TestUTLSDialUnknownHost(t *testing.T) {
	t.Parallel()

	utlsCfg := &utls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	_, err := UTLSDial("127.0.0.1:1", utlsCfg, utls.HelloChrome_Auto, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected error dialing unreachable host, got nil")
	}
}

// TestWebSocketLayerUTLSFlag verifies that setting UTLSEnabled=true on a
// WebSocketLayer propagates the field correctly (field presence test).
func TestWebSocketLayerUTLSFlag(t *testing.T) {
	t.Parallel()

	layer, err := NewWebSocketLayer("127.0.0.1:9999") // port unused
	if err != nil {
		t.Fatalf("NewWebSocketLayer: %v", err)
	}
	layer.UTLSEnabled = true
	layer.UTLSFingerprint = "firefox"
	layer.TLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only

	if !layer.UTLSEnabled {
		t.Error("UTLSEnabled should be true")
	}
	if layer.UTLSFingerprint != "firefox" {
		t.Errorf("UTLSFingerprint = %q, want %q", layer.UTLSFingerprint, "firefox")
	}
}

// TestHTTPConnectUTLSFlag mirrors TestWebSocketLayerUTLSFlag for HTTPConnect.
func TestHTTPConnectUTLSFlag(t *testing.T) {
	t.Parallel()

	hc, err := NewHTTPConnect("127.0.0.1:9999", "")
	if err != nil {
		t.Fatalf("NewHTTPConnect: %v", err)
	}
	hc.UTLSEnabled = true
	hc.UTLSFingerprint = "edge"
	hc.RelayTLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only

	if !hc.UTLSEnabled {
		t.Error("UTLSEnabled should be true")
	}
	if hc.UTLSFingerprint != "edge" {
		t.Errorf("UTLSFingerprint = %q, want %q", hc.UTLSFingerprint, "edge")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// buildSelfSignedCert generates a minimal self-signed TLS certificate for tests.
func buildSelfSignedCert(t *testing.T) (tls.Certificate, error) {
	t.Helper()
	return generateEphemeralTLSCert()
}

// generateEphemeralTLSCert creates an in-memory ECDSA P-256 self-signed certificate
// for loopback TLS tests.  Mirrors the logic in pkg/relay/tls_config.go to
// avoid creating an import cycle.
func generateEphemeralTLSCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}
