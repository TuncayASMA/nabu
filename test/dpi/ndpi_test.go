// Package dpi — nDPI classification integration tests.
//
// These tests verify that traffic shaped by the Micro-Phantom shaper is
// classified as "TLS" or "HTTPS" by nDPI (libndpi-bin ≥ 4.2).
//
// Skip conditions:
//   - ndpiReader binary not in PATH   → skip with message
//   - Test binary needs root to use   → handled; we only read pcap files
//
// Build-tag: none (runs in normal `go test ./test/dpi/...`)
package dpi

import (
	"context"
	"encoding/binary"
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
// PCAP helpers (pure Go, no CGO / gopacket)
// ─────────────────────────────────────────────────────────────────────────────

const (
	pcapMagic   = 0xa1b2c3d4
	pcapLinkEth = 1 // LINKTYPE_ETHERNET
)

// writePcapGlobalHeader writes the 24-byte PCAP file global header.
func writePcapGlobalHeader(f *os.File) error {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:], pcapMagic)
	binary.LittleEndian.PutUint16(buf[4:], 2)            // version major
	binary.LittleEndian.PutUint16(buf[6:], 4)            // version minor
	binary.LittleEndian.PutUint32(buf[8:], 0)            // thiszone (UTC)
	binary.LittleEndian.PutUint32(buf[12:], 0)           // sigfigs
	binary.LittleEndian.PutUint32(buf[16:], 65535)       // snaplen
	binary.LittleEndian.PutUint32(buf[20:], pcapLinkEth) // network
	_, err := f.Write(buf)
	return err
}

// writePcapRecord writes one PCAP record (16-byte header + data).
func writePcapRecord(f *os.File, data []byte, tsSec, tsUsec uint32) error {
	l := uint32(len(data))
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:], tsSec)
	binary.LittleEndian.PutUint32(buf[4:], tsUsec)
	binary.LittleEndian.PutUint32(buf[8:], l)
	binary.LittleEndian.PutUint32(buf[12:], l)
	if _, err := f.Write(buf); err != nil {
		return err
	}
	_, err := f.Write(data)
	return err
}

// buildEthernetFrame wraps payload in Ethernet + IPv4 + TCP headers.
// IHL = 20 (no options), TCP data offset = 5 (no options).
// Checksums are left at 0 — nDPI does not validate them.
func buildEthernetFrame(payload []byte, srcPort, dstPort uint16) []byte {
	ipTotalLen := 20 + 20 + len(payload)
	frame := make([]byte, 0, 14+ipTotalLen)

	// Ethernet (14 bytes): dst MAC, src MAC, EtherType IPv4 (0x0800)
	frame = append(frame,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src
		0x08, 0x00, // EtherType
	)

	// IPv4 (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45                                           // version=4 IHL=5
	binary.BigEndian.PutUint16(ip[2:], uint16(ipTotalLen)) // total length
	binary.BigEndian.PutUint16(ip[4:], 0x1234)             // ID
	ip[8] = 64                                             // TTL
	ip[9] = 6                                              // protocol TCP
	ip[12] = 192
	ip[13] = 168
	ip[14] = 1
	ip[15] = 100 // src 192.168.1.100
	ip[16] = 1
	ip[17] = 1
	ip[18] = 1
	ip[19] = 1 // dst 1.1.1.1
	frame = append(frame, ip...)

	// TCP (20 bytes): PSH | ACK
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], 1000)  // seq
	binary.BigEndian.PutUint32(tcp[8:], 0)     // ack
	tcp[12] = 0x50                             // data offset = 5 (20 bytes)
	tcp[13] = 0x18                             // PSH + ACK
	binary.BigEndian.PutUint16(tcp[14:], 8192) // window
	frame = append(frame, tcp...)
	frame = append(frame, payload...)
	return frame
}

// tlsClientHello builds a minimal TLS 1.3 ClientHello record that nDPI
// recognises as TLS traffic.  The random field is filled with actual
// pseudo-random bytes so entropy is high.
func tlsClientHello(rng *rand.Rand) []byte {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(rng.Intn(256))
	}

	// Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
	// Extensions: server_name (0x0000) → "example.com"
	sni := "example.com"
	sniExt := make([]byte, 0, 9+len(sni))
	sniExt = append(sniExt, 0x00, 0x00) // ext type: server_name
	sniExtDataLen := 2 + 1 + 2 + byte(len(sni))
	sniExt = append(sniExt, 0x00, sniExtDataLen)    // ext data length
	sniExt = append(sniExt, 0x00, byte(len(sni)+3)) // list length
	sniExt = append(sniExt, 0x00)                   // name type: host_name
	sniExt = append(sniExt, 0x00, byte(len(sni)))   // name length
	sniExt = append(sniExt, []byte(sni)...)

	body := make([]byte, 0, 100)
	body = append(body, 0x03, 0x03) // client version TLS 1.2 (TLS 1.3 uses extensions)
	body = append(body, random...)  // random (32 bytes)
	body = append(body, 0x00)       // session id length = 0
	body = append(body, 0x00, 0x04) // cipher suites length = 4
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x13, 0x02) // TLS_AES_256_GCM_SHA384
	body = append(body, 0x01, 0x00) // compression methods (null)
	extLen := uint16(len(sniExt))
	body = append(body, byte(extLen>>8), byte(extLen))
	body = append(body, sniExt...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // HandshakeType: ClientHello
	bLen := len(body)
	handshake = append(handshake, byte(bLen>>16), byte(bLen>>8), byte(bLen))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16)       // ContentType: Handshake
	record = append(record, 0x03, 0x01) // legacy record version TLS 1.0
	rLen := len(handshake)
	record = append(record, byte(rLen>>8), byte(rLen))
	record = append(record, handshake...)
	return record
}

// ─────────────────────────────────────────────────────────────────────────────
// ndpiReader helpers
// ─────────────────────────────────────────────────────────────────────────────

// ndpiReaderPath returns the path to ndpiReader or "" if not found.
func ndpiReaderPath() string {
	path, err := exec.LookPath("ndpiReader")
	if err != nil {
		return ""
	}
	return path
}

// runNDPI runs ndpiReader on a pcap file and returns combined stdout+stderr.
func runNDPI(pcapPath string) (string, error) {
	bin := ndpiReaderPath()
	if bin == "" {
		return "", fmt.Errorf("ndpiReader not found in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-i", pcapPath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// TestNDPI_TLSClientHello verifies that a pcap containing TLS ClientHello
// packets is classified as "TLS" by ndpiReader.
func TestNDPI_TLSClientHello(t *testing.T) {
	if ndpiReaderPath() == "" {
		t.Skip("ndpiReader not in PATH — install libndpi-bin to run this test")
	}

	f, err := os.CreateTemp("", "nabu_tls_*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	defer os.Remove(f.Name())

	if err := writePcapGlobalHeader(f); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	rng := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic test
	for i := 0; i < 5; i++ {
		ch := tlsClientHello(rng)
		frame := buildEthernetFrame(ch, uint16(10000+i), 443)
		if err := writePcapRecord(f, frame, uint32(1700000000+i), 0); err != nil {
			t.Fatalf("write record %d: %v", i, err)
		}
	}
	f.Close()

	out, err := runNDPI(f.Name())
	if err != nil {
		// ndpiReader exits 0 even on empty pcap; any non-zero is a real error
		t.Logf("ndpiReader output:\n%s", out)
		t.Fatalf("ndpiReader failed: %v", err)
	}

	outLower := strings.ToLower(out)
	if !strings.Contains(outLower, "tls") && !strings.Contains(outLower, "https") {
		t.Logf("ndpiReader output:\n%s", out)
		t.Errorf("expected 'TLS' or 'HTTPS' in ndpiReader output, got nothing matching")
	}
}

// TestNDPI_PhantomShapedTraffic captures 32 KB of Phantom-shaped traffic
// through a net.Pipe, writes it as TCP packets into a pcap, then asserts
// that ndpiReader classifies it as TLS (or at worst Unknown — not as a
// known-malicious protocol like BitTorrent, P2P, or VPN).
func TestNDPI_PhantomShapedTraffic(t *testing.T) {
	if ndpiReaderPath() == "" {
		t.Skip("ndpiReader not in PATH — install libndpi-bin to run this test")
	}

	prof, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	// Send 32 KB through the shaper → collect all bytes.
	client, server := net.Pipe()
	defer server.Close()
	// client is closed explicitly in the write loop to unblock the reader.

	s, err := shaper.New(client, prof, shaper.Options{})
	if err != nil {
		t.Fatalf("shaper.New: %v", err)
	}

	const totalBytes = 32 * 1024
	collected := make([]byte, 0, totalBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for len(collected) < totalBytes {
			server.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
			n, readErr := server.Read(buf)
			if n > 0 {
				collected = append(collected, buf[:n]...)
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Write side — runs until goroutine signals done or context expires.
	rng := rand.New(rand.NewSource(99)) //nolint:gosec
	payload := make([]byte, 1400)
	for {
		for i := range payload {
			payload[i] = byte(rng.Intn(256))
		}
		client.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		if _, werr := s.Write(payload); werr != nil {
			break
		}
		select {
		case <-done:
			goto waitDone
		case <-ctx.Done():
			goto waitDone
		default:
		}
	}

waitDone:
	// Close client so the reader goroutine unblocks if still waiting.
	client.Close()
	select {
	case <-done:
	case <-ctx.Done():
	}

	if len(collected) == 0 {
		t.Fatal("no bytes collected from shaper")
	}

	// Wrap collected bytes as TLS application data records so nDPI sees a
	// plausible TLS 1.3 stream.
	f, err := os.CreateTemp("", "nabu_shaped_*.pcap")
	if err != nil {
		t.Fatalf("create temp pcap: %v", err)
	}
	defer os.Remove(f.Name())

	if err := writePcapGlobalHeader(f); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	// First packet: TLS ClientHello so nDPI initiates TLS state machine.
	rng2 := rand.New(rand.NewSource(777)) //nolint:gosec
	ch := tlsClientHello(rng2)
	frame := buildEthernetFrame(ch, 20000, 443)
	if err := writePcapRecord(f, frame, 1700000000, 0); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}

	// Subsequent packets: TLS ApplicationData records (content type 0x17).
	chunkSize := 1300
	seqOffset := uint32(1001)
	for offset := 0; offset < len(collected); offset += chunkSize {
		end := offset + chunkSize
		if end > len(collected) {
			end = len(collected)
		}
		chunk := collected[offset:end]
		// Wrap as TLS ApplicationData
		appData := make([]byte, 5+len(chunk))
		appData[0] = 0x17 // ContentType: ApplicationData
		appData[1] = 0x03
		appData[2] = 0x03 // TLS 1.2 record version
		binary.BigEndian.PutUint16(appData[3:], uint16(len(chunk)))
		copy(appData[5:], chunk)

		pkt := buildEthernetFrame(appData, 20000, 443)
		if err := writePcapRecord(f, pkt, uint32(1700000000)+seqOffset/1000, seqOffset%1000); err != nil {
			t.Fatalf("write record: %v", err)
		}
		seqOffset++
	}
	f.Close()

	out, err := runNDPI(f.Name())
	if err != nil {
		t.Logf("ndpiReader output:\n%s", out)
		t.Fatalf("ndpiReader failed: %v", err)
	}

	t.Logf("ndpiReader output (truncated):\n%.2000s", out)

	outLower := strings.ToLower(out)

	// Primary assertion: classified as TLS or HTTPS
	isTLS := strings.Contains(outLower, "tls") || strings.Contains(outLower, "https")

	// Negative assertion: must not be a known VPN/P2P/malware protocol
	blockedProtos := []string{
		"bittorrent", "p2p", "openvpn", "wireguard", "tor",
		"i2p", "shadowsocks", "obfs", "quicdoq",
	}
	for _, proto := range blockedProtos {
		if strings.Contains(outLower, proto) {
			t.Errorf("ndpiReader detected fingerprinted protocol %q — DPI bypass failed", proto)
		}
	}

	if !isTLS {
		// Acceptable fallback: "Unknown" is fine (not fingerprinted as VPN)
		if strings.Contains(outLower, "unknown") {
			t.Logf("WARN: classified as Unknown (not TLS) — acceptable for encrypted payload without SNI")
		} else {
			t.Errorf("expected TLS or HTTPS classification, got unrecognised output")
		}
	}
}
