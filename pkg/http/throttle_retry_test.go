package http

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func newLimitedRequester(t *testing.T) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	opts.Timeout = 5 * time.Second
	if err := network.Init(opts); err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.NewHostRateLimiter(ratelimit.HostRateLimiterConfig{MaxPerHost: 4, WafAutoArm: true})
	t.Cleanup(func() { _ = lim.Close() })
	svc := &services.Services{Options: opts, HostLimiter: lim}
	svc.Egress = egress.New(egress.Config{Hosts: lim})
	r, err := NewRequester(opts, svc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.CloseIdleConnections)
	return r
}

// MISS-22: a 429 is retried transparently after the host's pause; the module
// sees the 200 and the retry lands >= 1s after the throttle.
func TestThrottle_429ThenOK(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		n := len(times)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	r := newLimitedRequester(t).WithAbandonFlag(&atomic.Bool{})
	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/x")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Close()
	if got := resp.Response().StatusCode; got != http.StatusOK {
		t.Fatalf("status = %d, want 200 after the transparent retry", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(times) != 2 {
		t.Fatalf("server hits = %d, want 2", len(times))
	}
	if gap := times[1].Sub(times[0]); gap < 900*time.Millisecond {
		t.Errorf("retry gap = %v, want >= ~1s", gap)
	}
	if n := r.CallStats().Throttled.Load(); n != 0 {
		t.Errorf("Throttled = %d, want 0 (the module got a real answer)", n)
	}
}

// A host that keeps throttling: the final 429 reaches the module and the
// call is marked Throttled.
func TestThrottle_PersistentMarksCall(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	r := newLimitedRequester(t).WithAbandonFlag(&atomic.Bool{})
	rr, _ := httpmsg.GetRawRequestFromURL(srv.URL + "/x")
	resp, _, err := r.Execute(rr, Options{NoClustering: true})
	if err != nil {
		t.Fatal(err)
	}
	resp.Close()
	if n := hits.Load(); n != 1+maxThrottleRetries {
		t.Errorf("hits = %d, want %d", n, 1+maxThrottleRetries)
	}
	if n := r.CallStats().Throttled.Load(); n != 1 {
		t.Errorf("Throttled = %d, want 1", n)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d := ParseRetryAfter("5", now); d != 5*time.Second {
		t.Errorf("seconds: %v", d)
	}
	if d := ParseRetryAfter(now.Add(10*time.Second).Format(http.TimeFormat), now); d != 10*time.Second {
		t.Errorf("http-date: %v", d)
	}
	for _, v := range []string{"", "-1", "soon"} {
		if d := ParseRetryAfter(v, now); d != 0 {
			t.Errorf("%q: %v, want 0", v, d)
		}
	}
}
