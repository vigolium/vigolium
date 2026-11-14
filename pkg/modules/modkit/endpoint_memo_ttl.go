package modkit

import (
	"errors"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
)

// memoEntry is one EndpointMemo value and when it stops being served.
type memoEntry struct {
	value   any
	expires time.Time // zero = no expiry
}

func (sc *ScanContext) getEndpointMemoCache() *lru.Cache[string, memoEntry] {
	sc.endpointMemoOnce.Do(func() {
		sc.endpointMemoCache, _ = lru.New[string, memoEntry](measurementCacheSize)
	})
	return sc.endpointMemoCache
}

// EndpointMemo is EndpointMeasurement for a non-int value with an optional
// TTL: a property derived by probing the record's UNMODIFIED request, shared by
// every insertion point (and every module that asks under the same name) of
// that record, with concurrent first callers collapsed into one compute.
//
// compute returns the value and whether to cache it: a transient failure
// (transport error, dead host) should return cache=false so the next caller
// re-measures instead of inheriting the failure. ttl <= 0 caches for the life
// of the ScanContext. A nil ScanContext computes directly.
func (sc *ScanContext) EndpointMemo(name string, ctx *httpmsg.HttpRequestResponse, ttl time.Duration, compute func() (any, bool)) any {
	if compute == nil {
		return nil
	}
	if sc == nil || ctx == nil || ctx.Request() == nil {
		v, _ := compute()
		return v
	}
	key := name + "\x00" + ctx.Request().ID()
	cache := sc.getEndpointMemoCache()
	fresh := func() (any, bool) {
		if e, ok := cache.Get(key); ok && (e.expires.IsZero() || time.Now().Before(e.expires)) {
			return e.value, true
		}
		return nil, false
	}
	if v, ok := fresh(); ok {
		return v
	}
	res, _, _ := sc.endpointMemoFlight.Do(key, func() (interface{}, error) {
		if v, ok := fresh(); ok {
			return v, nil
		}
		v, keep := compute()
		if keep {
			e := memoEntry{value: v}
			if ttl > 0 {
				e.expires = time.Now().Add(ttl)
			}
			cache.Add(key, e)
		}
		return v, nil
	})
	return res
}

// TimingBaselineKey namespaces the shared time-based-oracle baseline. Bump the
// version when the threshold formula changes.
const TimingBaselineKey = "timing-baseline-v1"

// timingBaselineTTL bounds how long one latency model is reused: long enough
// to cover every insertion point of a record and the other timing module, short
// enough that a host whose latency drifts is re-measured.
const timingBaselineTTL = 2 * time.Minute

// Timing-threshold parameters shared by every time-based oracle (sqli_time_blind,
// command_injection_timing). The memo key is shared too, so the formula must be.
const (
	TimingBaselineSamples  = 4
	timingStdevCoeff       = 5
	timingMinSleepMargin   = 3 * time.Second
	timingAbsoluteFloor    = 2 * time.Second
	timingBaselineBlockedV = int64(-1)
)

// ErrTimingBaselineBlocked: the record's unmodified request is answered by a
// WAF/CDN block, auth gate or rate limit — there is no application latency to
// model, so a time-based oracle must skip the record.
var ErrTimingBaselineBlocked = errors.New("timing baseline: unmodified request is blocked")

// TimingSample sends the record's unmodified request once and reports its
// latency and whether the response was a block.
type TimingSample func() (elapsed time.Duration, blocked bool, err error)

// TimingThreshold returns the delay a sleep payload must exceed on this record:
// max(floor, mean + max(5·stdev, 3s)) over TimingBaselineSamples unmodified
// requests. It is measured lazily, once per record across insertion points and
// across timing modules (memo key TimingBaselineKey, value threshold ns or -1
// when blocked) instead of four baseline requests per point per module
// (ECON-6). A transport error is returned and not cached.
func (sc *ScanContext) TimingThreshold(ctx *httpmsg.HttpRequestResponse, sample TimingSample) (time.Duration, error) {
	var sampleErr error
	v := sc.EndpointMemo(TimingBaselineKey, ctx, timingBaselineTTL, func() (any, bool) {
		samples := make([]time.Duration, 0, TimingBaselineSamples)
		for i := 0; i < TimingBaselineSamples; i++ {
			d, blocked, err := sample()
			if err != nil {
				sampleErr = err
				return int64(0), false
			}
			if blocked {
				return timingBaselineBlockedV, true
			}
			samples = append(samples, d)
		}
		mean, stdev := infra.MeanStdev(samples)
		margin := time.Duration(timingStdevCoeff) * stdev
		if margin < timingMinSleepMargin {
			margin = timingMinSleepMargin
		}
		threshold := mean + margin
		if threshold < timingAbsoluteFloor {
			threshold = timingAbsoluteFloor
		}
		return int64(threshold), true
	})
	if sampleErr != nil {
		return 0, sampleErr
	}
	ns, _ := v.(int64)
	switch {
	case ns == timingBaselineBlockedV:
		return 0, ErrTimingBaselineBlocked
	case ns <= 0:
		// A concurrent caller's measurement failed (not cached); report it as
		// blocked-equivalent so this point is skipped rather than timed blind.
		return 0, ErrTimingBaselineBlocked
	}
	return time.Duration(ns), nil
}

// UnmodifiedTimingSample sends the record's own request (unmodified) once —
// no redirects, no response clustering (a cached copy would collapse the
// jitter estimate) — and reports the requester-measured elapsed time and
// whether the answer was a block.
func UnmodifiedTimingSample(ctx *httpmsg.HttpRequestResponse, client *http.Requester) TimingSample {
	return func() (time.Duration, bool, error) {
		req := httpmsg.NewRequestResponseRaw(ctx.Request().Raw(), ctx.Service())
		resp, elapsed, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
		if err != nil {
			return 0, false, err
		}
		blocked := infra.IsBlockedResponse(resp)
		resp.Close()
		return elapsed, blocked, nil
	}
}
