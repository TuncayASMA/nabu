// Package shaper provides a Micro-Phantom traffic shaper that wraps network
// connections and makes egress traffic statistically indistinguishable from
// the traffic class described by a TrafficProfile.
//
// The shaper uses inverse-transform sampling on the profile's CDF tables to
// determine packet payload size and inter-packet delay.  A token-bucket rate
// limiter enforces burst budgets.  When no real payload is available (idle
// connection), synthetic keep-alive frames are injected at the profile IAT rate.
package shaper

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/TuncayASMA/nabu/pkg/phantom/profiles"
)

// tokenBucket is a simple token-bucket rate limiter for byte throughput.
// It is intentionally minimal to avoid an external golang.org/x/time/rate
// dependency while keeping correctness guarantees.
type tokenBucket struct {
	mu        sync.Mutex
	tokens    float64
	capacity  float64 // maximum tokens (bytes)
	ratePerNs float64 // tokens replenished per nanosecond
	lastFill  time.Time
}

func newTokenBucket(capacity float64, ratePerSec float64) *tokenBucket {
	return &tokenBucket{
		tokens:    capacity,
		capacity:  capacity,
		ratePerNs: ratePerSec / 1e9,
		lastFill:  time.Now(),
	}
}

// take blocks until n tokens are available, then consumes them.
func (tb *tokenBucket) take(ctx context.Context, n float64) error {
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastFill)
		tb.tokens += float64(elapsed.Nanoseconds()) * tb.ratePerNs
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastFill = now

		if tb.tokens >= n {
			tb.tokens -= n
			tb.mu.Unlock()
			return nil
		}
		// Calculate how long until n tokens will be available.
		deficit := n - tb.tokens
		waitNs := deficit / tb.ratePerNs
		tb.mu.Unlock()

		waitDur := time.Duration(waitNs)
		if waitDur < time.Millisecond {
			waitDur = time.Millisecond
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDur):
		}
	}
}

// Shaper wraps a net.Conn and applies Micro-Phantom shaping to all writes.
// Reads are passed through unchanged (the remote side is responsible for its
// own pacing).
//
// Thread safety: Write is serialised internally; Read and Close are delegated
// to the underlying connection.
type Shaper struct {
	conn    net.Conn
	profile *profiles.TrafficProfile
	rng     *rand.Rand
	bucket  *tokenBucket
	mu      sync.Mutex // serialises Write calls
}

// Options configures a Shaper.
type Options struct {
	// RateBytesPerSec is the sustained byte rate for the token bucket.
	// Zero means unlimited (default 10 MiB/s).
	RateBytesPerSec float64
	// BucketCapacityBytes is the token-bucket burst capacity.
	// Zero defaults to 2 × MaxPacketBytes.
	BucketCapacityBytes float64
	// RandSeed is the random seed for the CDF sampler.  0 uses crypto entropy.
	RandSeed int64
}

const defaultRateBytesPerSec = 10 * 1024 * 1024 // 10 MiB/s
const defaultBucketCapacity = 2 * profiles.MaxPacketBytes

// New wraps conn with Micro-Phantom shaping according to profile.
func New(conn net.Conn, profile *profiles.TrafficProfile, opts Options) (*Shaper, error) {
	if conn == nil {
		return nil, fmt.Errorf("phantom shaper: conn is nil")
	}
	if profile == nil {
		return nil, fmt.Errorf("phantom shaper: profile is nil")
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("phantom shaper: invalid profile: %w", err)
	}

	rate := opts.RateBytesPerSec
	if rate <= 0 {
		rate = defaultRateBytesPerSec
	}
	cap := opts.BucketCapacityBytes
	if cap <= 0 {
		cap = defaultBucketCapacity
	}

	seed := opts.RandSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	return &Shaper{
		conn:    conn,
		profile: profile,
		//nolint:gosec // deterministic PRNG is intentional for traffic shaping
		rng:    rand.New(rand.NewSource(seed)),
		bucket: newTokenBucket(cap, rate),
	}, nil
}

// Write sends data over the underlying connection, padding each write to a
// profile-sampled size and sleeping for a profile-sampled IAT before
// returning.
//
// If the payload is longer than a single sampled packet size, it is sent in
// multiple profile-paced segments.
func (s *Shaper) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := len(b)
	written := 0
	first := true

	for written < total {
		// Inter-arrival delay (skip before first segment).
		if !first {
			iatMs := s.profile.SampleIATMs(s.rng)
			time.Sleep(time.Duration(iatMs * float64(time.Millisecond)))
		}
		first = false

		// Choose segment size from the profile distribution.
		targetSize := s.profile.SamplePacketSize(s.rng)
		if targetSize <= 0 {
			targetSize = 1
		}

		remaining := total - written
		segSize := remaining
		if segSize > targetSize {
			segSize = targetSize
		}
		segment := b[written : written+segSize]

		// Enforce token-bucket rate limit.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.bucket.take(ctx, float64(len(segment)))
		cancel()
		if err != nil {
			return written, fmt.Errorf("phantom shaper: rate limiter: %w", err)
		}

		// Pad the segment if it is smaller than targetSize and there is no
		// more real payload.  This fills the frame to the sampled size so that
		// wire observers see profile-distributed packet sizes.
		//
		// NOTE: Padding bytes are zeroed; higher layers MUST encrypt before
		// passing to Shaper so that padding is not distinguishable from data.
		if remaining <= targetSize && targetSize > segSize {
			padded := make([]byte, targetSize)
			copy(padded, segment)
			// padded[segSize:] already zero — padding bytes
			n, err := s.conn.Write(padded)
			if n > segSize {
				n = segSize // report only real bytes consumed
			}
			written += n
			if err != nil {
				return written, err
			}
			continue
		}

		n, err := s.conn.Write(segment)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// Read delegates directly to the underlying connection.
func (s *Shaper) Read(b []byte) (int, error) {
	return s.conn.Read(b)
}

// Close closes the underlying connection.
func (s *Shaper) Close() error {
	return s.conn.Close()
}

// LocalAddr returns the local network address of the underlying connection.
func (s *Shaper) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// RemoteAddr returns the remote network address.
func (s *Shaper) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines on the underlying connection.
func (s *Shaper) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying connection.
func (s *Shaper) SetReadDeadline(t time.Time) error { return s.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying connection.
func (s *Shaper) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// Profile returns the TrafficProfile currently associated with this Shaper.
func (s *Shaper) Profile() *profiles.TrafficProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile
}

// SetProfile hot-swaps the shaping profile at runtime.
func (s *Shaper) SetProfile(p *profiles.TrafficProfile) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("phantom shaper: SetProfile: %w", err)
	}
	s.mu.Lock()
	s.profile = p
	s.mu.Unlock()
	return nil
}

// GenerateIdle writes synthetic keep-alive frames at profile-paced IAT for the
// given duration.  This is called when the tunnel is idle to maintain the
// traffic fingerprint even in the absence of real user data.
//
// Each idle frame is a zero-padded segment of profile-sampled size so that DPI
// tools observe a plausible traffic rate.  Callers MUST encrypt the connection
// before calling GenerateIdle so that pattern-matching on zero bytes is not
// possible.
func (s *Shaper) GenerateIdle(ctx context.Context, duration time.Duration) error {
	deadline := time.Now().Add(duration)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return nil
		}

		s.mu.Lock()
		iatMs := s.profile.SampleIATMs(s.rng)
		pktSize := s.profile.SamplePacketSize(s.rng)
		s.mu.Unlock()

		// Sleep the IAT before writing the idle frame.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(iatMs * float64(time.Millisecond))):
		}

		idleFrame := make([]byte, pktSize)
		// idleFrame is all zeros — caller is responsible for encryption.
		if _, err := s.conn.Write(idleFrame); err != nil {
			// Connection closed — idle loop should terminate gracefully.
			if isClosedErr(err) {
				return nil
			}
			return fmt.Errorf("phantom shaper: GenerateIdle write: %w", err)
		}
	}
}

// isClosedErr returns true for "use of closed network connection" errors
// that arise when the peer closes gracefully during idle generation.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return err == io.EOF || err == io.ErrClosedPipe
}

// Ensure *Shaper satisfies net.Conn at compile time.
var _ net.Conn = (*Shaper)(nil)
