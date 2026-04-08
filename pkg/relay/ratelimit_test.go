package relay

import (
	"sync"
	"testing"
	"time"
)

// TestTokenBucketAllow verifies that a fresh bucket allows up to burst packets.
func TestTokenBucketAllow(t *testing.T) {
	t.Parallel()
	// rate=10 pps, burst=5 → the bucket starts with 5 tokens.
	tb := NewTokenBucket(10, 5)

	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Fatalf("expected Allow()=true on token %d (bucket not empty)", i+1)
		}
	}
}

// TestTokenBucketExhausted verifies that the bucket rejects once tokens are depleted.
func TestTokenBucketExhausted(t *testing.T) {
	t.Parallel()
	tb := NewTokenBucket(10, 3)

	// Drain the bucket.
	for i := 0; i < 3; i++ {
		tb.Allow()
	}

	if tb.Allow() {
		t.Fatal("expected Allow()=false after bucket exhausted")
	}
}

// TestTokenBucketRefill verifies that waiting lets the bucket replenish.
func TestTokenBucketRefill(t *testing.T) {
	t.Parallel()
	// rate=100 pps → 1 token every 10 ms, burst=1.
	tb := NewTokenBucket(100, 1)

	if !tb.Allow() {
		t.Fatal("expected first Allow()=true")
	}
	if tb.Allow() {
		t.Fatal("expected Allow()=false after burst exhausted")
	}

	// Wait long enough for one token to refill.
	time.Sleep(15 * time.Millisecond)

	if !tb.Allow() {
		t.Fatal("expected Allow()=true after refill")
	}
}

// TestRateLimiterMapIsolation verifies that two distinct addresses have independent buckets.
func TestRateLimiterMapIsolation(t *testing.T) {
	t.Parallel()
	m := NewRateLimiterMap(10, 1) // burst=1 means one packet per burst

	// Both addresses should get their first packet through.
	if !m.Allow("1.2.3.4:1234") {
		t.Fatal("first packet for addr A should be allowed")
	}
	if !m.Allow("5.6.7.8:5678") {
		t.Fatal("first packet for addr B should be allowed")
	}

	// Both buckets now exhausted (burst=1).
	if m.Allow("1.2.3.4:1234") {
		t.Fatal("second packet for addr A should be dropped")
	}
	if m.Allow("5.6.7.8:5678") {
		t.Fatal("second packet for addr B should be dropped")
	}
}

// TestTokenBucketConcurrency checks that concurrent Allow calls don't race.
// rate=1 pps so the bucket refills at most once per second — far slower than
// the test completes, making the burst=100 assertion deterministic even under
// the race detector.
func TestTokenBucketConcurrency(t *testing.T) {
	t.Parallel()
	tb := NewTokenBucket(1, 100)
	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- tb.Allow()
		}()
	}
	wg.Wait()
	close(allowed)

	count := 0
	for ok := range allowed {
		if ok {
			count++
		}
	}
	// burst=100 so at most 100 goroutines should be allowed.
	if count > 100 {
		t.Fatalf("too many goroutines allowed: got %d, burst=100", count)
	}
}
