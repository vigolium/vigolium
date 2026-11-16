package config

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/types"
)

// withRateCeiling sets VIGOLIUM_RATE_CEILING for one test, with a fresh clamp
// log whose notices go to the returned buffer.
func withRateCeiling(t *testing.T, value string) *bytes.Buffer {
	t.Helper()
	t.Setenv(RateCeilingEnv, value)
	var out bytes.Buffer
	rateClamps.Lock()
	prevSeen, prevList, prevOut := rateClamps.seen, rateClamps.list, rateClamps.out
	rateClamps.seen, rateClamps.list, rateClamps.out = nil, nil, &out
	rateClamps.Unlock()
	t.Cleanup(func() {
		rateClamps.Lock()
		rateClamps.seen, rateClamps.list, rateClamps.out = prevSeen, prevList, prevOut
		rateClamps.Unlock()
	})
	return &out
}

func TestParseRateCeiling(t *testing.T) {
	for raw, want := range map[string]RateCeiling{"": 0, "  ": 0, "10": 10, "0.5": 0.5, " 2.5 ": 2.5} {
		got, err := ParseRateCeiling(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, want, got, raw)
	}
	// A safety ceiling that does not parse is refused, never read as "none".
	for _, bad := range []string{"0", "-1", "abc", "NaN", "Inf", "10rps"} {
		_, err := ParseRateCeiling(bad)
		require.Error(t, err, bad)
		assert.Contains(t, err.Error(), RateCeilingEnv)
	}
}

func TestRateCeilingClampRules(t *testing.T) {
	var none RateCeiling
	assert.Equal(t, 100, none.IntRate(100), "no ceiling: unchanged")
	assert.Equal(t, 0, none.IntRate(0), "no ceiling: unlimited stays unlimited")
	assert.InDelta(t, 0.0, none.Rate(0), 0)

	c := RateCeiling(10)
	assert.Equal(t, 10, c.IntRate(100), "above: lowered")
	assert.Equal(t, 5, c.IntRate(5), "below: untouched")
	assert.Equal(t, 10, c.IntRate(10), "at: untouched")
	assert.Equal(t, 10, c.IntRate(0), "unlimited: the ceiling")
	assert.InDelta(t, 10.0, c.Rate(0), 0, "unlimited fractional rate: the ceiling")
	assert.InDelta(t, 2.5, c.Rate(2.5), 0)
	assert.Equal(t, 10, c.IntRate(25))
	assert.Equal(t, 10, c.IntRate(0), "a default count is clamped too")

	// Fractional ceilings are exact on fractional dials and 1 on whole ones.
	half := RateCeiling(0.5)
	assert.InDelta(t, 0.5, half.Rate(100), 0)
	assert.Equal(t, 1, half.IntRate(100))
	assert.Equal(t, 1, half.IntRate(40))
	assert.Equal(t, 7, RateCeiling(7.9).IntRate(100), "whole dials floor the ceiling")
}

func TestCeilReportsEachDialOnce(t *testing.T) {
	out := withRateCeiling(t, "10")
	assert.Equal(t, 10, CeilIntRate("--rate-limit", 100))
	assert.Equal(t, 10, CeilIntRate("--rate-limit", 50))
	assert.Equal(t, 5, CeilIntRate("--rate-limit-other", 5), "a value under the ceiling is not a clamp")
	assert.Equal(t, 10, CeilIntRate("--concurrency", 25))

	clamps := RateClamps()
	require.Len(t, clamps, 2)
	assert.Equal(t, RateClamp{Dial: "--rate-limit", From: 100, To: 10}, clamps[0])
	assert.Equal(t, RateClamp{Dial: "--concurrency", From: 25, To: 10}, clamps[1])
	assert.Equal(t, 2, bytes.Count(out.Bytes(), []byte("\n")), "one stderr line per dial")
	assert.Contains(t, out.String(), "VIGOLIUM_RATE_CEILING=10: --rate-limit lowered from 100 to 10")
}

func TestCeilUnsetIsANoOp(t *testing.T) {
	out := withRateCeiling(t, "")
	assert.Equal(t, 100, CeilIntRate("--rate-limit", 100))
	assert.InDelta(t, 0.0, CeilRate("finding verify --rate-limit", 0), 0)
	opts := &types.Options{RateLimit: 100, Concurrency: 25, MaxPerHost: 40}
	CeilOptionsPace(opts)
	assert.Equal(t, types.Options{RateLimit: 100, Concurrency: 25, MaxPerHost: 40}, *opts)
	pace := DefaultScanningPaceConfig()
	pace.CeilPace()
	assert.Equal(t, DefaultScanningPaceConfig(), pace)
	assert.Empty(t, RateClamps())
	assert.Empty(t, out.String())
}

func TestCeilOptionsAndPace(t *testing.T) {
	withRateCeiling(t, "8")
	opts := &types.Options{RateLimit: 100, Concurrency: 25, MaxPerHost: 4}
	CeilOptionsPace(opts)
	assert.Equal(t, 8, opts.RateLimit)
	assert.Equal(t, 8, opts.Concurrency)
	assert.Equal(t, 4, opts.MaxPerHost, "below the ceiling: untouched")

	pace := DefaultScanningPaceConfig()
	pace.AdaptivePerHost = true
	pace.KnownIssueScan.RateLimit = 50
	pace.Probe.Concurrency = 3
	pace.CeilPace()
	assert.Equal(t, 8, pace.RateLimit)
	assert.Equal(t, 8, pace.Concurrency)
	assert.Equal(t, 8, pace.MaxPerHost)
	assert.Equal(t, 8, pace.MaxPerHostCeiling, "the adaptive ramp stops at the ceiling")
	assert.Equal(t, 8, pace.KnownIssueScan.RateLimit)
	assert.Equal(t, 3, pace.Probe.Concurrency)
	assert.Equal(t, 0, pace.Discovery.RateLimit, "a zero section value still inherits")
}

func TestPaceResolversHonourTheCeiling(t *testing.T) {
	withRateCeiling(t, "10")
	pace := DefaultScanningPaceConfig()
	// Discovery is unpaced unless a rate is explicit; under a ceiling it runs
	// at the ceiling.
	assert.Equal(t, 10, pace.DiscoveryRateLimit(&types.Options{RateLimit: 100}))
	// The known-issue scan's own 20 rps default is above a ceiling of 10.
	assert.Equal(t, 10, pace.KnownIssueScanRateLimit(&types.Options{}))
	// A concurrency factor cannot take a phase past it.
	pace.DynamicAssessment.ConcurrencyFactor = 4
	r := pace.ResolvePhase("dynamic-assessment")
	assert.Equal(t, 10, r.Concurrency)
	assert.Equal(t, 10, r.RateLimit)

	withRateCeiling(t, "50")
	assert.Equal(t, KnownIssueScanDefaultRateLimit, DefaultScanningPaceConfig().KnownIssueScanRateLimit(&types.Options{}),
		"a default under the ceiling is untouched")
}
