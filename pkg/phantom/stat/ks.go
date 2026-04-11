// Package stat provides statistical test utilities for the Micro-Phantom
// traffic-profile validation suite.
//
// The primary export is KSTest, a pure-Go implementation of the
// two-sample one-sided Kolmogorov-Smirnov test used to verify that traffic
// shaped by a TrafficProfile matches the expected CDF distribution.
package stat

import (
	"math"
	"sort"
)

// KSTest computes the Kolmogorov-Smirnov statistic D comparing an empirical
// sample against a reference CDF.
//
// sample is a slice of observed values, normalised to [0, 1] by the caller
// (divide packet sizes by MaxPacketBytes, IAT values by MaxIATMs, etc.).
//
// cdf is a monotone non-decreasing CDF slice of length n; cdf[i] is the
// cumulative probability for value (i+1)/n of the maximum.  The CDF must
// satisfy cdf[len(cdf)-1] == 1.0.
//
// Returns:
//   - D: the maximum vertical distance between the empirical CDF and the
//     reference CDF (Kolmogorov-Smirnov statistic).
//   - pValue: the approximate asymptotic p-value using the KS distribution.
//     Values > 0.05 indicate a statistically acceptable match.
func KSTest(sample []float64, cdf []float64) (D float64, pValue float64) {
	if len(sample) == 0 || len(cdf) == 0 {
		return 0, 1
	}
	n := len(sample)
	sorted := make([]float64, n)
	copy(sorted, sample)
	sort.Float64s(sorted)

	var dMax float64
	for i, x := range sorted {
		empirical := float64(i+1) / float64(n)
		ref := referenceCDF(x, cdf)
		d := math.Abs(empirical - ref)
		if d > dMax {
			dMax = d
		}
		// Also check the step before this point.
		empiricalPrev := float64(i) / float64(n)
		d2 := math.Abs(empiricalPrev - ref)
		if d2 > dMax {
			dMax = d2
		}
	}

	p := ksPValue(dMax, n)
	return dMax, p
}

// referenceCDF evaluates the piecewise-linear CDF at normalised value x ∈ [0,1].
func referenceCDF(x float64, cdf []float64) float64 {
	if x <= 0 {
		return 0
	}
	if x >= 1 {
		return 1
	}
	n := len(cdf)
	// Each bucket i covers x ∈ ((i)/n, (i+1)/n].
	// We linearly interpolate between adjacent CDF values.
	pos := x * float64(n) // position in [0, n]
	lo := int(pos)
	if lo >= n {
		return cdf[n-1]
	}
	frac := pos - float64(lo)
	var cdfLo float64
	if lo > 0 {
		cdfLo = cdf[lo-1]
	}
	cdfHi := cdf[lo]
	return cdfLo + frac*(cdfHi-cdfLo)
}

// BucketFrequencyTest checks whether an observed sample is consistent with
// a reference CDF by comparing bucket counts.
//
// It divides sample into the same len(cdf) buckets as the profile CDF and
// checks that each bucket's observed probability is within tolerance of the
// expected probability derived from the CDF.
//
// tolerance is the maximum allowed relative deviation per bucket (e.g. 0.50
// means the observed probability for bucket i must be within ±50% of expected).
// Buckets with expected probability < minExpected (e.g. 0.01) are skipped.
//
// Returns true if all checked buckets pass, false otherwise.
func BucketFrequencyTest(sample []float64, cdf []float64, tolerance float64) bool {
	if len(sample) == 0 || len(cdf) == 0 {
		return true
	}
	n := len(cdf)
	// Compute per-bucket expected probabilities from the CDF.
	counts := make([]int, n)
	for _, x := range sample {
		b := int(x * float64(n))
		if b >= n {
			b = n - 1
		}
		if b < 0 {
			b = 0
		}
		counts[b]++
	}
	total := float64(len(sample))
	for i := 0; i < n; i++ {
		var expectedP float64
		if i == 0 {
			expectedP = cdf[0]
		} else {
			expectedP = cdf[i] - cdf[i-1]
		}
		if expectedP < 0.01 {
			continue // skip very unlikely buckets
		}
		observedP := float64(counts[i]) / total
		// Check that |observed - expected| / expected <= tolerance
		if math.Abs(observedP-expectedP)/expectedP > tolerance {
			return false
		}
	}
	return true
}

// ksPValue returns the asymptotic p-value for KS statistic D and sample size n.
// Uses the Kolmogorov distribution approximation:
//
// P(D_n > d) ≈ 2 * Σ_{k=1}^{∞} (-1)^{k-1} exp(-2k²t²)   where t = d*sqrt(n)
//
// We sum until convergence (20 terms max; the series converges rapidly).
func ksPValue(D float64, n int) float64 {
	if D == 0 {
		return 1
	}
	t := D * math.Sqrt(float64(n))
	var sum float64
	for k := 1; k <= 20; k++ {
		term := math.Exp(-2 * float64(k*k) * t * t)
		if k%2 == 1 {
			sum += term
		} else {
			sum -= term
		}
		if math.Abs(term) < 1e-15 {
			break
		}
	}
	p := 2 * sum
	if p < 0 {
		return 0
	}
	if p > 1 {
		return 1
	}
	return p
}

// ShannonEntropy computes the Shannon entropy (bits) of a byte slice.
// For ideal random (AES-GCM) ciphertext this should be ≈ 8 bits/byte.
// For compressed/plaintext streams it is typically lower.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
