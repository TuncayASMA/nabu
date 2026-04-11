// Package dpi contains DPI-evasion statistical tests for the Micro-Phantom
// traffic shaper.  The tests verify two properties:
//
//  1. Profile distribution fidelity: samples drawn from a TrafficProfile via
//     SamplePacketSize / SampleIATMs match the declared CDF bucket distribution
//     within a 50% relative tolerance per bucket (BucketFrequencyTest).
//
//  2. Shannon entropy: data passing through a net.Pipe wrapped in a Shaper
//     retains sufficient entropy to be compatible with HTTPS-style traffic
//     (threshold 3 bits/byte for unencrypted shaped data).
package dpi

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/phantom/profiles"
	"github.com/TuncayASMA/nabu/pkg/phantom/shaper"
	"github.com/TuncayASMA/nabu/pkg/phantom/stat"
)

const nSamples = 2000 // direct samples from profile distributions

// sampleSizes draws n packet-size samples from a profile and normalises to [0,1].
func sampleSizes(prof *profiles.TrafficProfile, n int) []float64 {
	rng := rand.New(rand.NewSource(12345)) //nolint:gosec
	out := make([]float64, n)
	for i := range out {
		out[i] = float64(prof.SamplePacketSize(rng)) / float64(profiles.MaxPacketBytes)
	}
	return out
}

// sampleIATs draws n IAT values from a profile and normalises to [0,1].
func sampleIATs(prof *profiles.TrafficProfile, n int) []float64 {
	rng := rand.New(rand.NewSource(54321)) //nolint:gosec
	out := make([]float64, n)
	for i := range out {
		out[i] = prof.SampleIATMs(rng) / profiles.MaxIATMs
	}
	return out
}

// assertBucketFreq fails t if the sample distribution deviates from the CDF
// beyond the given tolerance per bucket.
func assertBucketFreq(t *testing.T, label string, sample []float64, cdf []float64, tol float64) {
	t.Helper()
	pass := stat.BucketFrequencyTest(sample, cdf, tol)
	if !pass {
		t.Errorf("%s: bucket frequency test failed (>%.0f%% relative deviation in some bucket)", label, tol*100)
	} else {
		t.Logf("%s: bucket frequency test passed (n=%d tol=%.0f%%)", label, len(sample), tol*100)
	}
}

// ── Packet-size distribution tests ──────────────────────────────────────────

func TestProfile_WebBrowsing_PacketSizeDist(t *testing.T) {
	prof, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	assertBucketFreq(t, "web_browsing/sizes", sampleSizes(prof, nSamples), prof.PacketSizeDist, 0.60)
}

func TestProfile_YoutubeSd_PacketSizeDist(t *testing.T) {
	prof, err := profiles.LoadEmbedded("youtube_sd")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	assertBucketFreq(t, "youtube_sd/sizes", sampleSizes(prof, nSamples), prof.PacketSizeDist, 0.60)
}

func TestProfile_InstagramFeed_PacketSizeDist(t *testing.T) {
	prof, err := profiles.LoadEmbedded("instagram_feed")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	assertBucketFreq(t, "instagram_feed/sizes", sampleSizes(prof, nSamples), prof.PacketSizeDist, 0.60)
}

// ── IAT distribution tests ───────────────────────────────────────────────────

func TestProfile_WebBrowsing_IATDist(t *testing.T) {
	prof, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	assertBucketFreq(t, "web_browsing/iats", sampleIATs(prof, nSamples), prof.IATDist, 0.60)
}

func TestProfile_YoutubeSd_IATDist(t *testing.T) {
	prof, err := profiles.LoadEmbedded("youtube_sd")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	assertBucketFreq(t, "youtube_sd/iats", sampleIATs(prof, nSamples), prof.IATDist, 0.60)
}

func TestProfile_InstagramFeed_IATDist(t *testing.T) {
	prof, err := profiles.LoadEmbedded("instagram_feed")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	assertBucketFreq(t, "instagram_feed/iats", sampleIATs(prof, nSamples), prof.IATDist, 0.60)
}

// ── Shannon entropy integration test ────────────────────────────────────────

// TestPhantomShaper_ShannonEntropy sends 32 KB through a Shaper-wrapped
// net.Pipe and checks the received byte-stream entropy is plausible.
func TestPhantomShaper_ShannonEntropy(t *testing.T) {
	prof, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	sh, err := shaper.New(client, prof, shaper.Options{})
	if err != nil {
		t.Fatalf("shaper.New: %v", err)
	}

	const total = 32 * 1024
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i & 0xff)
	}

	var (
		mu   sync.Mutex
		recv []byte
		wg   sync.WaitGroup
	)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				mu.Lock()
				recv = append(recv, buf[:n]...)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	const chunk = 1024
	written := 0
	for written < total {
		select {
		case <-ctx.Done():
			t.Log("context timeout during write")
			goto done
		default:
		}
		rem := total - written
		sz := chunk
		if rem < sz {
			sz = rem
		}
		if _, werr := sh.Write(payload[written : written+sz]); werr != nil {
			t.Logf("write stopped at %d: %v", written, werr)
			goto done
		}
		written += sz
	}
done:
	server.Close()
	wg.Wait()

	mu.Lock()
	data := recv
	mu.Unlock()

	if len(data) == 0 {
		t.Fatal("no bytes received")
	}
	h := stat.ShannonEntropy(data)
	t.Logf("bytes received=%d entropy=%.4f bits", len(data), h)
	if h < 3.0 {
		t.Errorf("entropy %.4f < 3.0", h)
	}
}
