package stat

import (
	"math"
	"math/rand"
	"testing"
)

// uniformCDF returns a 20-point CDF for a uniform [0,1] distribution.
func uniformCDF() []float64 {
	cdf := make([]float64, 20)
	for i := range cdf {
		cdf[i] = float64(i+1) / 20.0
	}
	return cdf
}

// sampleUniform generates n samples uniformly in [0,1] using the given seed.
func sampleUniform(n int, seed int64) []float64 {
	r := rand.New(rand.NewSource(seed)) //nolint:gosec // deterministic test seed
	s := make([]float64, n)
	for i := range s {
		s[i] = r.Float64()
	}
	return s
}

// TestKSTest_SameDistribution: sampling from a uniform distribution and
// testing against the uniform CDF should yield a high p-value (no rejection).
func TestKSTest_SameDistribution(t *testing.T) {
	sample := sampleUniform(500, 42)
	cdf := uniformCDF()
	D, p := KSTest(sample, cdf)
	t.Logf("same dist: D=%.4f p=%.4f", D, p)
	if p < 0.05 {
		t.Errorf("expected p >= 0.05 for same distribution, got %.4f (D=%.4f)", p, D)
	}
}

// TestKSTest_DifferentDistribution: a constant sample (all 0.99) vs uniform CDF
// should yield a very small p-value (distributions clearly differ).
func TestKSTest_DifferentDistribution(t *testing.T) {
	sample := make([]float64, 200)
	for i := range sample {
		sample[i] = 0.99
	}
	cdf := uniformCDF()
	D, p := KSTest(sample, cdf)
	t.Logf("diff dist: D=%.4f p=%.6f", D, p)
	if p >= 0.05 {
		t.Errorf("expected p < 0.05 for very different distribution, got %.6f (D=%.4f)", p, D)
	}
}

// TestKSTest_EmptySample should return D=0, p=1 without panic.
func TestKSTest_EmptySample(t *testing.T) {
	D, p := KSTest(nil, uniformCDF())
	if D != 0 || p != 1 {
		t.Errorf("empty sample: expected D=0 p=1, got D=%v p=%v", D, p)
	}
}

// TestKSTest_EmptyCDF should return D=0, p=1 without panic.
func TestKSTest_EmptyCDF(t *testing.T) {
	D, p := KSTest([]float64{0.5}, nil)
	if D != 0 || p != 1 {
		t.Errorf("empty CDF: expected D=0 p=1, got D=%v p=%v", D, p)
	}
}

// TestKSTest_SinglePoint: one-element sample equal to 0.5.
func TestKSTest_SinglePoint(t *testing.T) {
	D, p := KSTest([]float64{0.5}, uniformCDF())
	t.Logf("single point 0.5: D=%.4f p=%.4f", D, p)
	if D < 0 || D > 1 {
		t.Errorf("D out of range: %v", D)
	}
	if p < 0 || p > 1 {
		t.Errorf("p out of range: %v", p)
	}
}

// TestReferenceCDF_Boundaries verifies edge-case handling of the step-function CDF.
func TestReferenceCDF_Boundaries(t *testing.T) {
	cdf := uniformCDF()
	if v := referenceCDF(0, cdf); v != 0 {
		t.Errorf("referenceCDF(0)=%v, want 0", v)
	}
	if v := referenceCDF(1, cdf); v != 1 {
		t.Errorf("referenceCDF(1)=%v, want 1", v)
	}
	v := referenceCDF(0.5, cdf)
	if math.Abs(v-0.5) > 0.1 {
		t.Errorf("referenceCDF(0.5)=%v, want ≈0.5", v)
	}
}

// TestKSPValue_Large: very large D → p≈0.
func TestKSPValue_Large(t *testing.T) {
	p := ksPValue(1.0, 1000)
	if p > 0.001 {
		t.Errorf("ksPValue(1.0,1000)=%v, want ≈0", p)
	}
}

// TestShannonEntropy_Random: 10 000 bytes of CSPRNG data should be close to 8 bits.
func TestShannonEntropy_Random(t *testing.T) {
	r := rand.New(rand.NewSource(7)) //nolint:gosec // deterministic seed
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(r.Intn(256))
	}
	h := ShannonEntropy(data)
	t.Logf("random entropy: %.4f bits", h)
	if h < 7.8 {
		t.Errorf("expected entropy >= 7.8 for random data, got %.4f", h)
	}
}

// TestShannonEntropy_Zeros: all-zero byte slice should have entropy 0.
func TestShannonEntropy_Zeros(t *testing.T) {
	data := make([]byte, 1000)
	h := ShannonEntropy(data)
	if h != 0 {
		t.Errorf("expected entropy=0 for zeros, got %v", h)
	}
}

// TestShannonEntropy_TwoSymbols: alternating 0x00/0x01 → entropy=1.0.
func TestShannonEntropy_TwoSymbols(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 2)
	}
	h := ShannonEntropy(data)
	if math.Abs(h-1.0) > 0.01 {
		t.Errorf("expected entropy≈1.0 for two-symbol stream, got %v", h)
	}
}

// TestShannonEntropy_Empty: empty slice → entropy=0.
func TestShannonEntropy_Empty(t *testing.T) {
	h := ShannonEntropy(nil)
	if h != 0 {
		t.Errorf("expected entropy=0 for empty, got %v", h)
	}
}

// TestBucketFrequencyTest_Uniform: uniform samples vs uniform CDF should pass.
func TestBucketFrequencyTest_Uniform(t *testing.T) {
	sample := sampleUniform(2000, 99)
	cdf := uniformCDF()
	if !BucketFrequencyTest(sample, cdf, 0.50) {
		t.Error("expected BucketFrequencyTest to pass for uniform vs uniform CDF")
	}
}

// TestBucketFrequencyTest_AllZeros: samples all at 0 vs uniform CDF should fail.
func TestBucketFrequencyTest_AllZeros(t *testing.T) {
	sample := make([]float64, 500)
	cdf := uniformCDF()
	if BucketFrequencyTest(sample, cdf, 0.50) {
		t.Error("expected BucketFrequencyTest to fail when all samples are 0")
	}
}

// TestBucketFrequencyTest_EmptySample: empty sample should return true (vacuous).
func TestBucketFrequencyTest_EmptySample(t *testing.T) {
	if !BucketFrequencyTest(nil, uniformCDF(), 0.50) {
		t.Error("expected vacuous pass for empty sample")
	}
}
