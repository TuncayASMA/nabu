package shaper_test

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TuncayASMA/nabu/pkg/phantom/profiles"
	"github.com/TuncayASMA/nabu/pkg/phantom/shaper"
)

// --- helpers ---

// pipeConn returns a pair of connected in-process net.Conn.
func pipeConn() (net.Conn, net.Conn) {
	return net.Pipe()
}

// loadWeb returns the web_browsing profile (panics on error).
func loadWeb(t *testing.T) *profiles.TrafficProfile {
	t.Helper()
	p, err := profiles.LoadEmbedded("web_browsing")
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	return p
}

// --- New ---

func TestNew_NilConn(t *testing.T) {
	p := loadWeb(t)
	_, err := shaper.New(nil, p, shaper.Options{})
	if err == nil {
		t.Error("expected error for nil conn, got nil")
	}
}

func TestNew_NilProfile(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	_, err := shaper.New(c1, nil, shaper.Options{})
	if err == nil {
		t.Error("expected error for nil profile, got nil")
	}
}

func TestNew_InvalidProfile(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	bad := &profiles.TrafficProfile{Name: ""} // fails Validate
	_, err := shaper.New(c1, bad, shaper.Options{})
	if err == nil {
		t.Error("expected error for invalid profile, got nil")
	}
}

func TestNew_OK(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	p := loadWeb(t)
	s, err := shaper.New(c1, p, shaper.Options{RandSeed: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil Shaper")
	}
}

// --- Profile / SetProfile ---

func TestProfile_ReturnsInitial(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{RandSeed: 2})
	if s.Profile().Name != "web_browsing" {
		t.Errorf("Profile().Name = %q, want web_browsing", s.Profile().Name)
	}
}

func TestSetProfile_SwapsProfile(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	web := loadWeb(t)
	s, _ := shaper.New(c1, web, shaper.Options{RandSeed: 3})
	yt, _ := profiles.LoadEmbedded("youtube_sd")
	if err := s.SetProfile(yt); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	if s.Profile().Name != "youtube_sd" {
		t.Errorf("after SetProfile, Name = %q, want youtube_sd", s.Profile().Name)
	}
}

func TestSetProfile_Invalid(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{RandSeed: 4})
	bad := &profiles.TrafficProfile{Name: ""}
	if err := s.SetProfile(bad); err == nil {
		t.Error("expected error for invalid profile, got nil")
	}
}

// --- net.Conn interface ---

func TestShaper_ImplementsNetConn(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	defer c2.Close()
	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{RandSeed: 5})
	var _ net.Conn = s // compile-time check (also runtime)
	_ = s.LocalAddr()
	_ = s.RemoteAddr()
}

// --- Write / Read ---

func TestWrite_SmallPayload(t *testing.T) {
	c1, c2 := pipeConn()
	defer c2.Close()
	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{RandSeed: 6, RateBytesPerSec: 10 * 1024 * 1024})

	payload := []byte("hello phantom")
	var wg sync.WaitGroup
	wg.Add(1)
	var received []byte
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		n, _ := c2.Read(buf)
		received = buf[:n]
	}()

	if _, err := s.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s.Close()
	wg.Wait()

	// The received slice may be padded; original payload must be a prefix.
	if len(received) < len(payload) {
		t.Fatalf("received %d bytes, want at least %d", len(received), len(payload))
	}
	if !bytes.Equal(received[:len(payload)], payload) {
		t.Errorf("payload mismatch: got %q, want %q", received[:len(payload)], payload)
	}
}

func TestWrite_LargePayload_MultiSegment(t *testing.T) {
	c1, c2 := pipeConn()
	defer c2.Close()

	// Use instagram profile (smaller average packets) + fixed seed.
	insta, err := profiles.LoadEmbedded("instagram_feed")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := shaper.New(c1, insta, shaper.Options{RandSeed: 7, RateBytesPerSec: 100 * 1024 * 1024})

	// Write 8 KiB which is larger than any single packet (max 1460 B).
	const dataLen = 8 * 1024
	data := make([]byte, dataLen)
	rand.New(rand.NewSource(0)).Read(data) //nolint:gosec

	var wg sync.WaitGroup
	var totalRead int
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for totalRead < dataLen {
			n, err2 := c2.Read(buf[totalRead:])
			totalRead += n
			if err2 != nil {
				break
			}
		}
	}()

	n, err := s.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != dataLen {
		t.Errorf("Write returned %d, want %d", n, dataLen)
	}
	s.Close()
	wg.Wait()
	// All real bytes must have arrived.
	if totalRead < dataLen {
		t.Errorf("received %d bytes, want at least %d", totalRead, dataLen)
	}
}

func TestRead_Passthrough(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{RandSeed: 8})

	msg := []byte("read passthrough test")
	go func() {
		_, _ = c2.Write(msg)
		c2.Close()
	}()

	buf := make([]byte, 256)
	n, err := s.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("Read got %q, want %q", buf[:n], msg)
	}
}

// --- GenerateIdle ---

func TestGenerateIdle_Cancels(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	// Drain c2 so writes don't block.
	go func() {
		io.Copy(io.Discard, c2) //nolint:errcheck
		c2.Close()
	}()

	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{RandSeed: 9, RateBytesPerSec: 100 * 1024 * 1024})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := s.GenerateIdle(ctx, 10*time.Second) // asks for 10s but context cuts it short
	elapsed := time.Since(start)

	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("GenerateIdle error = %v, want nil or context.DeadlineExceeded", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("GenerateIdle took %v, ctx should have cut it at ~50ms", elapsed)
	}
}

func TestGenerateIdle_DurationRespected(t *testing.T) {
	c1, c2 := pipeConn()
	defer c1.Close()
	go func() {
		io.Copy(io.Discard, c2) //nolint:errcheck
		c2.Close()
	}()

	p := loadWeb(t)
	s, _ := shaper.New(c1, p, shaper.Options{
		RandSeed:        10,
		RateBytesPerSec: 100 * 1024 * 1024,
	})

	ctx := context.Background()
	start := time.Now()
	idleDur := 30 * time.Millisecond
	err := s.GenerateIdle(ctx, idleDur)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("GenerateIdle: unexpected error: %v", err)
	}
	// Should have run for at least idleDur but not excessively longer.
	if elapsed < idleDur {
		t.Errorf("GenerateIdle returned in %v, want >= %v", elapsed, idleDur)
	}
	if elapsed > idleDur+500*time.Millisecond {
		t.Errorf("GenerateIdle took %v, want < %v", elapsed, idleDur+500*time.Millisecond)
	}
}
