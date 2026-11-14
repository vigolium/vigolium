package modkit

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func memoRecord() *httpmsg.HttpRequestResponse {
	return httpmsg.NewRequestResponseRaw([]byte("GET /x HTTP/1.1\r\nHost: m.test\r\n\r\n"),
		httpmsg.NewServiceSecure("m.test", 80, false))
}

func TestEndpointMemoTTLAndNoCacheOnFailure(t *testing.T) {
	sc := &ScanContext{}
	rec := memoRecord()
	var calls atomic.Int64
	compute := func() (any, bool) { calls.Add(1); return "v", true }

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); sc.EndpointMemo("k", rec, time.Hour, compute) }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent first callers computed %d times, want 1", calls.Load())
	}

	// Expiry: a short TTL re-measures.
	sc.EndpointMemo("short", rec, time.Millisecond, compute)
	time.Sleep(5 * time.Millisecond)
	sc.EndpointMemo("short", rec, time.Millisecond, compute)
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3 (expired entry re-measured)", calls.Load())
	}

	// cache=false is not stored.
	var fails atomic.Int64
	fail := func() (any, bool) { fails.Add(1); return nil, false }
	sc.EndpointMemo("fail", rec, time.Hour, fail)
	sc.EndpointMemo("fail", rec, time.Hour, fail)
	if fails.Load() != 2 {
		t.Fatalf("failed compute cached: %d calls", fails.Load())
	}
}

func TestTimingThresholdBlockedAndError(t *testing.T) {
	sc := &ScanContext{}
	rec := memoRecord()
	var sent atomic.Int64
	_, err := sc.TimingThreshold(rec, func() (time.Duration, bool, error) {
		sent.Add(1)
		return 0, true, nil
	})
	if !errors.Is(err, ErrTimingBaselineBlocked) {
		t.Fatalf("err = %v, want blocked", err)
	}
	// The blocked verdict is cached: no more samples.
	_, err = sc.TimingThreshold(rec, func() (time.Duration, bool, error) {
		sent.Add(1)
		return 10 * time.Millisecond, false, nil
	})
	if !errors.Is(err, ErrTimingBaselineBlocked) || sent.Load() != 1 {
		t.Fatalf("blocked verdict not memoised (err=%v sent=%d)", err, sent.Load())
	}

	other := httpmsg.NewRequestResponseRaw([]byte("GET /y HTTP/1.1\r\nHost: m.test\r\n\r\n"),
		httpmsg.NewServiceSecure("m.test", 80, false))
	boom := errors.New("dial refused")
	if _, err := sc.TimingThreshold(other, func() (time.Duration, bool, error) { return 0, false, boom }); !errors.Is(err, boom) {
		t.Fatalf("transport error not returned: %v", err)
	}
	th, err := sc.TimingThreshold(other, func() (time.Duration, bool, error) { return 10 * time.Millisecond, false, nil })
	// mean 10ms + the 3s minimum margin.
	if err != nil || th != 10*time.Millisecond+timingMinSleepMargin {
		t.Fatalf("threshold = %v, %v; want 3.01s", th, err)
	}
}
