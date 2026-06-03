package infra

import (
	"math"
	"time"
)

// MeanStdev computes the mean and population standard deviation of a set of
// durations. Shared by the time-based detection modules (sqli_time_blind,
// command_injection_timing) that derive an adaptive per-target delay threshold
// from a sample of baseline response times. Returns (0, 0) for an empty sample.
func MeanStdev(samples []time.Duration) (mean, stdev time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	mu := sum / float64(len(samples))
	var variance float64
	for _, s := range samples {
		d := float64(s) - mu
		variance += d * d
	}
	variance /= float64(len(samples))
	return time.Duration(mu), time.Duration(math.Sqrt(variance))
}
