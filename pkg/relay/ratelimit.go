package relay

import (
	"sync"
	"time"
)

// TokenBucket implements a token bucket rate limiter.
// Goroutine-safe; caller creates one per remote address.
type TokenBucket struct {
	rate   float64 // tokens added per second
	burst  float64 // maximum tokens (bucket capacity)
	tokens float64
	last   time.Time
	mu     sync.Mutex
}

// NewTokenBucket creates a new token bucket with the given rate (tokens/s) and
// burst capacity. The bucket starts full.
func NewTokenBucket(rate, burst int) *TokenBucket {
	return &TokenBucket{
		rate:   float64(rate),
		burst:  float64(burst),
		tokens: float64(burst),
		last:   time.Now(),
	}
}

// Allow reports whether a single token can be consumed.
// Returns true and decrements the token count when allowed; returns false when
// the bucket is empty (packet should be dropped).
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now

	// Refill tokens based on elapsed time, capped at burst.
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}

	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// RateLimiterMap manages one TokenBucket per remote address string.
type RateLimiterMap struct {
	rate    int
	burst   int
	buckets sync.Map // key: addr string, value: *TokenBucket
}

// NewRateLimiterMap creates a map whose buckets have the given rate and burst.
func NewRateLimiterMap(rate, burst int) *RateLimiterMap {
	return &RateLimiterMap{rate: rate, burst: burst}
}

// Allow returns true when the packet from addr should be forwarded.
func (m *RateLimiterMap) Allow(addr string) bool {
	v, _ := m.buckets.LoadOrStore(addr, NewTokenBucket(m.rate, m.burst))
	return v.(*TokenBucket).Allow()
}
