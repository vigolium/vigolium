package knownissuescan

import (
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

// TestDefaultRateLimitMatchesConfig keeps the phase's own default and the
// value the CLI/plan report in step.
func TestDefaultRateLimitMatchesConfig(t *testing.T) {
	if defaultRateLimit != config.KnownIssueScanDefaultRateLimit {
		t.Fatalf("knownissuescan default %d != config default %d", defaultRateLimit, config.KnownIssueScanDefaultRateLimit)
	}
}

// TestRequestCounterCountsSends: nuclei's progress hooks feed the request
// budget.
func TestRequestCounterCountsSends(t *testing.T) {
	var n atomic.Int64
	c := requestCounter{n: &n}
	c.IncrementRequests()
	c.SetRequests(3)
	c.IncrementFailedRequestsBy(2)
	c.IncrementMatched()
	c.AddToTotal(100)
	if n.Load() != 6 {
		t.Fatalf("counted %d, want 6", n.Load())
	}
	opts := buildEngineOptions(t.Context(), Config{Requests: &n}, nil)
	without := buildEngineOptions(t.Context(), Config{}, nil)
	if len(opts) != len(without)+1 {
		t.Fatalf("a Requests counter must add the stats-writer option (%d vs %d)", len(opts), len(without))
	}
}
