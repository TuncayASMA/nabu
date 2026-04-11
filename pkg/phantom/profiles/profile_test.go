package profiles_test

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/TuncayASMA/nabu/pkg/phantom/profiles"
)

func TestLoadEmbedded_AllNames(t *testing.T) {
	names := profiles.EmbeddedNames()
	if len(names) == 0 {
		t.Fatal("EmbeddedNames returned empty slice")
	}
	for _, name := range names {
		p, err := profiles.LoadEmbedded(name)
		if err != nil {
			t.Errorf("LoadEmbedded(%q): %v", name, err)
			continue
		}
		if p == nil {
			t.Errorf("LoadEmbedded(%q): returned nil", name)
		}
	}
}

func TestLoadEmbedded_Unknown(t *testing.T) {
	_, err := profiles.LoadEmbedded("nonexistent_profile")
	if err == nil {
		t.Fatal("expected error for unknown profile, got nil")
	}
}

func TestLoadEmbedded_WebBrowsing(t *testing.T) {
	p, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("LoadEmbedded(web_browsing): %v", err)
	}
	if p.Name != "web_browsing" {
		t.Errorf("Name = %q, want %q", p.Name, "web_browsing")
	}
}

func TestLoadEmbedded_YoutubeSd(t *testing.T) {
	p, err := profiles.LoadEmbedded("youtube_sd")
	if err != nil {
		t.Fatalf("LoadEmbedded(youtube_sd): %v", err)
	}
	if len(p.DNSPatterns) == 0 {
		t.Error("youtube_sd DNSPatterns is empty")
	}
}

func TestLoadEmbedded_InstagramFeed(t *testing.T) {
	p, err := profiles.LoadEmbedded("instagram_feed")
	if err != nil {
		t.Fatalf("LoadEmbedded(instagram_feed): %v", err)
	}
	if p.BurstPattern.MaxPackets <= p.BurstPattern.MinPackets {
		t.Errorf("instagram_feed BurstPattern invalid: max=%d <= min=%d",
			p.BurstPattern.MaxPackets, p.BurstPattern.MinPackets)
	}
}

func TestValidate_EmbeddedProfiles(t *testing.T) {
	for _, name := range profiles.EmbeddedNames() {
		p, _ := profiles.LoadEmbedded(name)
		if err := p.Validate(); err != nil {
			t.Errorf("Validate(%q): %v", name, err)
		}
	}
}

func TestValidate_EmptyName(t *testing.T) {
	p := &profiles.TrafficProfile{
		Name:           "",
		PacketSizeDist: make([]float64, 20),
		IATDist:        make([]float64, 20),
	}
	if err := p.Validate(); err == nil {
		t.Error("expected error for empty name, got nil")
	}
}

func TestValidate_WrongCDFLength(t *testing.T) {
	p := &profiles.TrafficProfile{
		Name:           "bad",
		PacketSizeDist: []float64{0.5, 1.0},
		IATDist:        make([]float64, 20),
	}
	if err := p.Validate(); err == nil {
		t.Error("expected error for wrong PacketSizeDist length, got nil")
	}
}

func TestValidate_NonMonotoneCDF(t *testing.T) {
	base, _ := profiles.LoadEmbedded("web_browsing")
	bad := *base
	dist := make([]float64, len(base.PacketSizeDist))
	copy(dist, base.PacketSizeDist)
	dist[5] = dist[4] - 0.01
	bad.PacketSizeDist = dist
	if err := bad.Validate(); err == nil {
		t.Error("expected error for non-monotone CDF, got nil")
	}
}

func TestValidate_CDFDoesNotReachOne(t *testing.T) {
	base, _ := profiles.LoadEmbedded("web_browsing")
	bad := *base
	dist := make([]float64, len(base.PacketSizeDist))
	copy(dist, base.PacketSizeDist)
	dist[19] = 0.90
	bad.PacketSizeDist = dist
	if err := bad.Validate(); err == nil {
		t.Error("expected error for CDF not reaching 1.0, got nil")
	}
}

func TestSamplePacketSize_InRange(t *testing.T) {
	p, _ := profiles.LoadEmbedded("web_browsing")
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		size := p.SamplePacketSize(rng)
		if size < 0 || size > profiles.MaxPacketBytes {
			t.Errorf("SamplePacketSize out of range: %d (want [0, %d])", size, profiles.MaxPacketBytes)
		}
	}
}

func TestSamplePacketSize_YoutubeLargerMean(t *testing.T) {
	web, _ := profiles.LoadEmbedded("web_browsing")
	yt, _ := profiles.LoadEmbedded("youtube_sd")
	rng := rand.New(rand.NewSource(99))
	var sumWeb, sumYt float64
	for i := 0; i < 5000; i++ {
		sumWeb += float64(web.SamplePacketSize(rng))
		sumYt += float64(yt.SamplePacketSize(rng))
	}
	if sumYt/5000 <= sumWeb/5000 {
		t.Errorf("youtube_sd mean size (%.1f) should be larger than web_browsing (%.1f)",
			sumYt/5000, sumWeb/5000)
	}
}

func TestSampleIATMs_InRange(t *testing.T) {
	p, _ := profiles.LoadEmbedded("instagram_feed")
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 1000; i++ {
		iat := p.SampleIATMs(rng)
		if iat < 0 || iat > profiles.MaxIATMs {
			t.Errorf("SampleIATMs out of range: %.2f (want [0, %.1f])", iat, profiles.MaxIATMs)
		}
	}
}

func TestLoadFromFile_RoundTrip(t *testing.T) {
	p, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(t.TempDir(), "web_browsing.json")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := profiles.LoadFromFile(tmp)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loaded.Name != p.Name {
		t.Errorf("Name mismatch after round-trip: %q vs %q", loaded.Name, p.Name)
	}
}

func TestLoadFromFile_BadPath(t *testing.T) {
	_, err := profiles.LoadFromFile("/nonexistent/path/profile.json")
	if err == nil {
		t.Error("expected error for bad path, got nil")
	}
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := profiles.LoadFromFile(tmp)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
