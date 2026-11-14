package stats

import (
	"math"
	"sync/atomic"
	"time"
)

// latencyBuckets is a lock-free log-scale histogram of completed module-call
// durations: bucket i holds calls in [2^(i/4) ms, 2^((i+1)/4) ms), i.e. four
// buckets per doubling (~19% resolution), from 1ms up to ~2^31.75 ms. Enough to
// read a p99 for the adaptive per-module timeout without storing
// samples.
type latencyBuckets struct {
	counts [128]atomic.Int64
	total  atomic.Int64
}

func latencyBucket(d time.Duration) int {
	ms := float64(d) / float64(time.Millisecond)
	if ms < 1 {
		return 0
	}
	i := int(math.Log2(ms) * 4)
	if i < 0 {
		return 0
	}
	if i >= 128 {
		return 127
	}
	return i
}

func (l *latencyBuckets) observe(d time.Duration) {
	l.counts[latencyBucket(d)].Add(1)
	l.total.Add(1)
}

// quantile returns the upper bound of the bucket holding quantile q (0..1),
// and the sample count.
func (l *latencyBuckets) quantile(q float64) (time.Duration, int64) {
	n := l.total.Load()
	if n == 0 {
		return 0, 0
	}
	rank := int64(math.Ceil(q * float64(n)))
	var seen int64
	for i := range l.counts {
		seen += l.counts[i].Load()
		if seen >= rank {
			upper := math.Pow(2, float64(i+1)/4) // ms
			return time.Duration(upper * float64(time.Millisecond)), n
		}
	}
	return time.Duration(math.Pow(2, 128.0/4) * float64(time.Millisecond)), n
}

// RecordCompletedDuration records the duration of a module call that finished
// inside its timeout, for the adaptive timeout's latency model. Calls that
// timed out or were interrupted must not be recorded: they would teach the
// model that the timeout itself is normal. Safe on a nil receiver.
func (ms *ModuleStats) RecordCompletedDuration(d time.Duration) {
	if ms != nil {
		ms.latency.observe(d)
	}
}

// LatencyQuantile returns moduleID's approximate completed-call latency at
// quantile q and the number of samples it is based on.
func (mm *ModuleMetrics) LatencyQuantile(moduleID string, q float64) (time.Duration, int64) {
	if mm == nil {
		return 0, 0
	}
	val, ok := mm.metrics.Load(moduleID)
	if !ok {
		return 0, 0
	}
	return val.(*ModuleStats).latency.quantile(q)
}
