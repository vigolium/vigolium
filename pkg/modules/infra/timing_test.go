package infra

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestMeanStdev verifies the shared baseline statistics helper used by the
// time-based detection modules.
func TestMeanStdev(t *testing.T) {
	t.Parallel()

	// Constant samples → zero deviation, mean equals the value.
	mean, stdev := MeanStdev([]time.Duration{
		100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond,
	})
	assert.Equal(t, 100*time.Millisecond, mean)
	assert.Equal(t, time.Duration(0), stdev)

	// Empty input is safe.
	mean, stdev = MeanStdev(nil)
	assert.Equal(t, time.Duration(0), mean)
	assert.Equal(t, time.Duration(0), stdev)

	// Known spread: values 0ms and 200ms → mean 100ms, population stdev 100ms.
	mean, stdev = MeanStdev([]time.Duration{0, 200 * time.Millisecond})
	assert.Equal(t, 100*time.Millisecond, mean)
	assert.Equal(t, 100*time.Millisecond, stdev)
}
