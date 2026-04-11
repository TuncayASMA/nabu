// Package profiles provides statistical traffic profiles derived from
// real-world browser traffic captures. Each profile encodes packet-size
// and inter-arrival-time (IAT) cumulative distribution functions so that
// the Phantom shaper can generate statistically indistinguishable traffic.
package profiles

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

// cdfPoints is the number of evenly-spaced samples in a CDF.
const cdfPoints = 20

// MaxPacketBytes is the maximum Ethernet-encapsulated payload we shape to.
const MaxPacketBytes = 1460

// MaxIATMs is the upper bound of the IAT distribution in milliseconds.
const MaxIATMs = 200.0

// Distribution describes a continuous variable with Gaussian-ish characteristics.
type Distribution struct {
	MinMs  float64 `json:"min_ms"`
	MaxMs  float64 `json:"max_ms"`
	MeanMs float64 `json:"mean_ms"`
	StdMs  float64 `json:"std_ms"`
}

// BurstModel captures bursty transmission behaviour.
type BurstModel struct {
	// MinPackets is the minimum number of packets in a single burst.
	MinPackets int `json:"min_packets"`
	// MaxPackets is the maximum number of packets in a single burst.
	MaxPackets int `json:"max_packets"`
	// PauseMeanMs is the mean duration (ms) between successive bursts.
	PauseMeanMs float64 `json:"pause_mean_ms"`
	// PauseStdMs is the standard deviation of inter-burst pauses (ms).
	PauseStdMs float64 `json:"pause_std_ms"`
}

// TrafficProfile is the statistical fingerprint of a browser traffic class.
//
// PacketSizeDist:
//
//	20-element CDF over the range [0, MaxPacketBytes].
//	PacketSizeDist[i] = P(size ≤ i * MaxPacketBytes/cdfPoints).
//
// IATDist:
//
//	20-element CDF over the range [0, MaxIATMs] milliseconds.
//	IATDist[i] = P(IAT ≤ i * MaxIATMs/cdfPoints).
type TrafficProfile struct {
	Name            string       `json:"name"`
	PacketSizeDist  []float64    `json:"packet_size_dist"` // len == cdfPoints
	IATDist         []float64    `json:"iat_dist"`         // len == cdfPoints
	BurstPattern    BurstModel   `json:"burst_pattern"`
	SessionDuration Distribution `json:"session_duration"`
	DNSPatterns     []string     `json:"dns_patterns"`
}

// Validate checks structural integrity of the profile.
func (p *TrafficProfile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("phantom profile: name is empty")
	}
	if len(p.PacketSizeDist) != cdfPoints {
		return fmt.Errorf("phantom profile %q: PacketSizeDist length %d != %d",
			p.Name, len(p.PacketSizeDist), cdfPoints)
	}
	if len(p.IATDist) != cdfPoints {
		return fmt.Errorf("phantom profile %q: IATDist length %d != %d",
			p.Name, len(p.IATDist), cdfPoints)
	}
	// CDFs must be non-decreasing and end at 1.0.
	for i := 1; i < cdfPoints; i++ {
		if p.PacketSizeDist[i] < p.PacketSizeDist[i-1] {
			return fmt.Errorf("phantom profile %q: PacketSizeDist not monotone at index %d", p.Name, i)
		}
		if p.IATDist[i] < p.IATDist[i-1] {
			return fmt.Errorf("phantom profile %q: IATDist not monotone at index %d", p.Name, i)
		}
	}
	if p.PacketSizeDist[cdfPoints-1] < 0.99 {
		return fmt.Errorf("phantom profile %q: PacketSizeDist does not reach 1.0 (got %.3f)",
			p.Name, p.PacketSizeDist[cdfPoints-1])
	}
	if p.IATDist[cdfPoints-1] < 0.99 {
		return fmt.Errorf("phantom profile %q: IATDist does not reach 1.0 (got %.3f)",
			p.Name, p.IATDist[cdfPoints-1])
	}
	return nil
}

// SamplePacketSize draws a packet-size sample from the CDF using inverse
// transform sampling. Result is in [0, MaxPacketBytes].
func (p *TrafficProfile) SamplePacketSize(rng *rand.Rand) int {
	u := rng.Float64()
	return sampleCDF(u, p.PacketSizeDist, MaxPacketBytes)
}

// SampleIATMs draws an IAT sample (milliseconds) from the CDF.
func (p *TrafficProfile) SampleIATMs(rng *rand.Rand) float64 {
	u := rng.Float64()
	return float64(sampleCDF(u, p.IATDist, int(MaxIATMs)))
}

// sampleCDF applies inverse-transform sampling against a discrete CDF.
// The CDF is assumed to cover the range [0, maxVal] with cdfPoints buckets.
// Returns an integer in [0, maxVal].
func sampleCDF(u float64, cdf []float64, maxVal int) int {
	n := len(cdf)
	for i, v := range cdf {
		if u <= v {
			// Map bucket index to value range.
			lo := (i * maxVal) / n
			hi := ((i + 1) * maxVal) / n
			if lo >= hi {
				return lo
			}
			// Uniform within the bucket.
			return lo + int(u*float64(hi-lo))
		}
	}
	return maxVal
}

// LoadFromFile reads and validates a JSON-encoded TrafficProfile from disk.
func LoadFromFile(path string) (*TrafficProfile, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("phantom profiles: read %q: %w", path, err)
	}
	var p TrafficProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("phantom profiles: parse %q: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadEmbedded returns the named built-in profile.
// name must be one of "web_browsing", "youtube_sd", "instagram_feed".
func LoadEmbedded(name string) (*TrafficProfile, error) {
	p, ok := embedded[name]
	if !ok {
		return nil, fmt.Errorf("phantom profiles: unknown embedded profile %q", name)
	}
	return p, nil
}

// EmbeddedNames returns the names of all built-in profiles.
func EmbeddedNames() []string {
	names := make([]string, 0, len(embedded))
	for k := range embedded {
		names = append(names, k)
	}
	return names
}
