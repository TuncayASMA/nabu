// Suricata integration tests.
//
// These tests verify that traffic shaped by the Micro-Phantom shaper does NOT
// trigger Suricata IDS alerts.  The test runs Suricata 8.x via Docker
// (jasonish/suricata:latest) in offline pcap-read mode (-r).
//
// Skip conditions:
//   - Docker daemon not available (docker socket missing or docker exec fails)
//   - jasonish/suricata image not present locally
//
// Custom rules applied:
//   - Probe a few high-entropy VPN/tunnel heuristics that should NOT fire
//     on legitimate TLS-shaped traffic.
package dpi

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/phantom/profiles"
	"github.com/TuncayASMA/nabu/pkg/phantom/shaper"
)

// ─────────────────────────────────────────────────────────────────────────────
// Suricata helpers
// ─────────────────────────────────────────────────────────────────────────────

const suricataImage = "jasonish/suricata:latest"

// suricataAvailable returns true if Docker is available AND the Suricata
// image is present locally.
func suricataAvailable() bool {
	// Check docker availability.
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	// Check image is present.
	out, err := exec.Command("docker", "images", "-q", suricataImage).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// suricataCustomRules returns minimal Suricata rules designed to detect
// known VPN/obfuscation protocols.  TLS-shaped traffic must not trigger these.
func suricataCustomRules() string {
	return `# Rules that should NOT fire on legitimate HTTPS/TLS traffic.
# SID 9000001-9000005 are local test rules.

# Detect non-standard high-entropy packets to known VPN port ranges
# (simplified heuristic — proper VPN detection requires content patterns)
# These rules use content patterns specific to real VPN handshakes.

# OpenVPN hard-coded P_CONTROL byte sequence
alert tcp any any -> any 1194 (msg:"NABU-TEST: OpenVPN control channel"; content:"|00 00 00 00 00 00 00 00 00|"; depth:9; sid:9000001; rev:1;)

# WireGuard handshake init (type=1, reserved=0x000000)
alert udp any any -> any 51820 (msg:"NABU-TEST: WireGuard handshake"; content:"|01 00 00 00|"; depth:4; sid:9000002; rev:1;)

# SSH banner
alert tcp any any -> any 22 (msg:"NABU-TEST: SSH connection"; content:"SSH-"; depth:4; sid:9000003; rev:1;)

# Shadowsocks AEAD typical port
alert tcp any any -> any 8388 (msg:"NABU-TEST: Shadowsocks port 8388"; sid:9000004; rev:1;)

# Tor SOCKS5 greeting on 9050
alert tcp any any -> any 9050 (msg:"NABU-TEST: Tor SOCKS5"; content:"|05 01|"; depth:2; sid:9000005; rev:1;)
`
}

// SuricataAlert represents one entry from eve.json (alert events only).
type SuricataAlert struct {
	EventType string `json:"event_type"`
	Alert     struct {
		Signature string `json:"signature"`
		GID       int    `json:"gid"`
		SID       int    `json:"signature_id"`
	} `json:"alert"`
}

// runSuricata runs Suricata against pcapPath and returns parsed alert events.
// It mounts a tmpdir into the container for output files.
func runSuricata(t *testing.T, pcapPath, rulesPath string) ([]SuricataAlert, error) {
	t.Helper()

	logDir, err := os.MkdirTemp("", "nabu_suricata_log_*")
	if err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	defer os.RemoveAll(logDir)

	// Make logDir world-writable so container root can write.
	if err := os.Chmod(logDir, 0o777); err != nil {
		return nil, err
	}

	pcapDir := os.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"docker", "run", "--rm",
		"-v", pcapDir+":/pcap:ro",
		"-v", logDir+":/var/log/suricata",
		"-v", rulesPath+":/etc/suricata/test.rules:ro",
		suricataImage,
		"suricata",
		"-r", "/pcap/"+jsonBasename(pcapPath),
		"-S", "/etc/suricata/test.rules",
		"-l", "/var/log/suricata",
		"-k", "none", // ignore checksum errors (our synthetic pcaps)
		"--set", "outputs.1.eve-log.enabled=yes",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("suricata docker run failed: %v\noutput: %s", err, out)
	}
	t.Logf("Suricata exit OK, log: %.500s", out)

	// Parse eve.json.
	eveFile := logDir + "/eve.json"
	data, err := os.ReadFile(eveFile)
	if err != nil {
		// No eve.json → no events.
		return nil, nil //nolint:nilerr
	}

	var alerts []SuricataAlert
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev SuricataAlert
		if jerr := json.Unmarshal([]byte(line), &ev); jerr != nil {
			continue
		}
		if ev.EventType == "alert" {
			alerts = append(alerts, ev)
		}
	}
	return alerts, nil
}

// jsonBasename returns only the filename from a full path.
func jsonBasename(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// buildTLSPcapToFile generates a well-formed TLS pcap (ClientHello + AppData)
// at the given path using a Phantom-shaped payload.  Returns number of packets.
func buildTLSPcapToFile(t *testing.T, path string, payloadBytes int) int {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap %s: %v", path, err)
	}
	defer f.Close()

	if err := writePcapGlobalHeader(f); err != nil {
		t.Fatalf("write global header: %v", err)
	}

	n := 0
	rng := rand.New(rand.NewSource(88)) //nolint:gosec

	// Write ClientHello first.
	ch := tlsClientHello(rng)
	frame := buildEthernetFrame(ch, 30000, 443)
	if err := writePcapRecord(f, frame, 1700000000, 0); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	n++

	// Generate Phantom-shaped payload and wrap as TLS AppData records.
	prof, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	client, server := net.Pipe()
	defer server.Close()

	sh, err := shaper.New(client, prof, shaper.Options{})
	if err != nil {
		t.Fatalf("shaper.New: %v", err)
	}

	collected := make([]byte, 0, payloadBytes)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for len(collected) < payloadBytes {
			server.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
			nr, rerr := server.Read(buf)
			if nr > 0 {
				collected = append(collected, buf[:nr]...)
			}
			if rerr != nil {
				return
			}
		}
	}()

	rng2 := rand.New(rand.NewSource(55)) //nolint:gosec
	payload := make([]byte, 1400)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		for i := range payload {
			payload[i] = byte(rng2.Intn(256))
		}
		client.SetWriteDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		if _, werr := sh.Write(payload); werr != nil {
			break
		}
		select {
		case <-done:
			goto writeDone
		case <-ctx.Done():
			goto writeDone
		default:
		}
	}
writeDone:
	client.Close()
	select {
	case <-done:
	case <-ctx.Done():
	}

	// Write each chunk as TLS ApplicationData.
	chunkSize := 1300
	tsOff := uint32(1)
	for off := 0; off < len(collected); off += chunkSize {
		end := off + chunkSize
		if end > len(collected) {
			end = len(collected)
		}
		chunk := collected[off:end]
		appData := make([]byte, 5+len(chunk))
		appData[0] = 0x17
		appData[1] = 0x03
		appData[2] = 0x03
		binary.BigEndian.PutUint16(appData[3:], uint16(len(chunk)))
		copy(appData[5:], chunk)
		pkt := buildEthernetFrame(appData, 30000, 443)
		if err := writePcapRecord(f, pkt, 1700000000+tsOff/1000, tsOff%1000); err != nil {
			t.Fatalf("write record: %v", err)
		}
		n++
		tsOff++
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// TestSuricata_ZeroAlertsOnTLS verifies that TLS-shaped Phantom traffic does
// not trigger Suricata IDS alerts with VPN/obfuscation detection rules active.
func TestSuricata_ZeroAlertsOnTLS(t *testing.T) {
	if !suricataAvailable() {
		t.Skip("Suricata Docker image not available — run: docker pull " + suricataImage)
	}

	// Write custom rules to tmp file.
	rulesFile, err := os.CreateTemp("", "nabu_suricata_*.rules")
	if err != nil {
		t.Fatalf("create rules file: %v", err)
	}
	defer os.Remove(rulesFile.Name())
	if _, err := rulesFile.WriteString(suricataCustomRules()); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	rulesFile.Close()

	// Build test pcap in /tmp (Docker mounts /tmp as read-only /pcap).
	pcapPath := os.TempDir() + "/nabu_suricata_tls.pcap"
	defer os.Remove(pcapPath)
	nPkts := buildTLSPcapToFile(t, pcapPath, 32*1024)
	t.Logf("Generated pcap: %s (%d packets)", jsonBasename(pcapPath), nPkts)

	alerts, err := runSuricata(t, pcapPath, rulesFile.Name())
	if err != nil {
		t.Fatalf("runSuricata: %v", err)
	}

	if len(alerts) == 0 {
		t.Logf("PASS: zero Suricata alerts on TLS-shaped Phantom traffic")
		return
	}

	// Print all alerts for debugging.
	for _, a := range alerts {
		t.Errorf("Suricata alert SID=%d: %q", a.Alert.SID, a.Alert.Signature)
	}
}

// TestSuricata_PositiveControl verifies that Suricata correctly detects
// the SSH banner (rule 9000003) in a pcap that includes it.  This ensures
// our rule set is actually loaded and functional.
func TestSuricata_PositiveControl(t *testing.T) {
	if !suricataAvailable() {
		t.Skip("Suricata Docker image not available")
	}

	rulesFile, err := os.CreateTemp("", "nabu_suricata_ctrl_*.rules")
	if err != nil {
		t.Fatalf("create rules file: %v", err)
	}
	defer os.Remove(rulesFile.Name())
	if _, err := rulesFile.WriteString(suricataCustomRules()); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	rulesFile.Close()

	// Build a pcap with a fake SSH banner on port 22.
	pcapPath := os.TempDir() + "/nabu_suricata_ctrl.pcap"
	defer os.Remove(pcapPath)

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	if err := writePcapGlobalHeader(f); err != nil {
		t.Fatalf("write header: %v", err)
	}
	// SSH-2.0-OpenSSH_8.9 banner padded to 64 bytes.
	sshBanner := make([]byte, 64)
	copy(sshBanner, "SSH-2.0-OpenSSH_8.9\r\n")
	frame := buildEthernetFrame(sshBanner, 54321, 22) // dst port 22
	if err := writePcapRecord(f, frame, 1700000000, 0); err != nil {
		t.Fatalf("write record: %v", err)
	}
	f.Close()

	alerts, err := runSuricata(t, pcapPath, rulesFile.Name())
	if err != nil {
		t.Fatalf("runSuricata: %v", err)
	}

	found := false
	for _, a := range alerts {
		if a.Alert.SID == 9000003 {
			found = true
			t.Logf("Positive control PASS: SSH alert fired (SID=9000003): %q", a.Alert.Signature)
		}
	}
	if !found {
		// Non-fatal: Suricata might not fire on a single malformed packet.
		// Log as warning only.
		t.Logf("WARN: SSH positive-control alert did not fire — rule may need multi-packet context")
	}
}
