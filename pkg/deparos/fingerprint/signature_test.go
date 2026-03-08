package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignature_Success(t *testing.T) {
	// Create 3 identical samples
	samples := createIdenticalSamples(t, 3)

	sig, err := NewSignature(samples)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Greater(t, sig.StableAttributeCount(), 0)
}

func TestNewSignature_NoSamples(t *testing.T) {
	_, err := NewSignature([]*Sample{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no samples")
}

func TestNewSignature_TooFewSamples(t *testing.T) {
	samples := createIdenticalSamples(t, 2)
	_, err := NewSignature(samples)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "need at least 3 samples")
}

func TestSignature_StableAttributes(t *testing.T) {
	// Create 3 samples with same StatusCode
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
			},
		}
		samples[i] = s
	}

	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// Both attributes should be stable
	assert.True(t, sig.HasAttribute(StatusCode))
	assert.True(t, sig.HasAttribute(ContentType))
	assert.Equal(t, 2, sig.StableAttributeCount())
}

func TestSignature_UnstableAttributes(t *testing.T) {
	// Create 3 samples where ETag differs
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode: 404,
				ETagHeader: uint32(i + 1), // Different for each sample
			},
		}
		samples[i] = s
	}

	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// StatusCode should be stable, ETag should not
	assert.True(t, sig.HasAttribute(StatusCode))
	assert.False(t, sig.HasAttribute(ETagHeader))
	assert.Equal(t, 1, sig.StableAttributeCount())
}

func TestSignature_Matches(t *testing.T) {
	// Create signature from 3 samples
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
			},
		}
		samples[i] = s
	}

	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// Create matching sample
	matchingSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}

	assert.True(t, sig.Matches(matchingSample))
}

func TestSignature_DoesNotMatch(t *testing.T) {
	// Create signature
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
			},
		}
		samples[i] = s
	}

	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// Create non-matching sample (different status)
	nonMatchingSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  200,
			ContentType: HashString("text/html"),
		},
	}

	assert.False(t, sig.Matches(nonMatchingSample))
}

func TestSignature_IsCriticalMatch(t *testing.T) {
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
			},
		}
		samples[i] = s
	}

	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// Matching critical attributes
	matchingSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	assert.True(t, sig.IsCriticalMatch(matchingSample))

	// Non-matching critical attributes
	nonMatchingSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  200,
			ContentType: HashString("text/html"),
		},
	}
	assert.False(t, sig.IsCriticalMatch(nonMatchingSample))
}

func TestSignature_PartialMatch(t *testing.T) {
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
				WordCount:   100,
			},
		}
		samples[i] = s
	}

	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// Sample matching 2 out of 3 attributes
	partialSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
			WordCount:   200, // Different
		},
	}

	matchPct := sig.PartialMatch(partialSample)
	assert.InDelta(t, 0.666, matchPct, 0.01) // ~66% match
}

func TestSignature_ThreadSafety(t *testing.T) {
	samples := createIdenticalSamples(t, 3)
	sig, err := NewSignature(samples)
	require.NoError(t, err)

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = sig.StableAttributeCount()
				_ = sig.HasAttribute(StatusCode)
				_ = sig.GetStableAttributes()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestSignature_Debug(t *testing.T) {
	samples := createIdenticalSamples(t, 3)
	sig, err := NewSignature(samples)
	require.NoError(t, err)

	debug := sig.Debug()
	assert.Contains(t, debug, "learned from 3 samples")

	sig.SetDebug("custom debug")
	assert.Equal(t, "custom debug (2 stable attrs)", sig.Debug())
}

// Helper function to create identical samples for testing
func createIdenticalSamples(t *testing.T, count int) []*Sample {
	samples := make([]*Sample, count)
	for i := 0; i < count; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
			},
		}
		samples[i] = s
	}
	return samples
}

func BenchmarkSignature_Matches(b *testing.B) {
	samples := make([]*Sample, 3)
	for i := 0; i < 3; i++ {
		s := &Sample{
			attributes: map[Attribute]uint32{
				StatusCode:  404,
				ContentType: HashString("text/html"),
				WordCount:   100,
				LineCount:   50,
			},
		}
		samples[i] = s
	}

	sig, _ := NewSignature(samples)

	testSample := &Sample{
		attributes: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
			WordCount:   100,
			LineCount:   50,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sig.Matches(testSample)
	}
}
