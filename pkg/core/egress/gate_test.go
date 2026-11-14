package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"golang.org/x/time/rate"
)

func newHosts(t *testing.T, perHost int) *ratelimit.HostRateLimiter {
	t.Helper()
	cfg := ratelimit.DefaultHostRateLimiterConfig()
	cfg.MaxPerHost = perHost
	cfg.AcquireTimeout = 5 * time.Second
	h := ratelimit.NewHostRateLimiter(cfg)
	t.Cleanup(func() { _ = h.Close() })
	return h
}

var errReset = errors.New("connection reset by peer")

func alwaysRetry(context.Context, error) bool { return true }

// Every wire attempt takes its own token: two failures and a success are three
// tokens and three counted attempts, not one.
func TestDo_TokenPerAttempt(t *testing.T) {
	lim := rate.NewLimiter(rate.Every(time.Hour), 3) // exactly three tokens, no refill
	g := New(Config{Rate: lim})

	calls := 0
	attempts, err := g.Do(context.Background(), "a.test:80", LaneNormal, RetryPolicy{
		MaxRetries: 5,
		Retryable:  alwaysRetry,
		Backoff:    func(int) time.Duration { return time.Millisecond },
	}, func(int, bool) error {
		calls++
		if calls < 3 {
			return errReset
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("Do = (%d, %v), want (3, nil)", attempts, err)
	}
	if got := g.Sent(); got != 3 {
		t.Fatalf("Sent = %d, want 3 (one per wire attempt)", got)
	}
	if tok := lim.Tokens(); tok > 0.01 {
		t.Fatalf("limiter has %.2f tokens left, want 0: a retry did not pay", tok)
	}
}

// The backoff before a retry is slept without the host slot: with one slot per
// host, another request to the same host gets through while the failing one
// waits to retry.
func TestDo_SlotReleasedDuringBackoff(t *testing.T) {
	g := New(Config{Hosts: newHosts(t, 1)})

	inBackoff := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		calls := 0
		_, err := g.Do(context.Background(), "a.test:80", LaneNormal, RetryPolicy{
			MaxRetries: 2,
			Retryable:  alwaysRetry,
			Backoff:    func(int) time.Duration { return 400 * time.Millisecond },
		}, func(int, bool) error {
			calls++
			if calls == 1 {
				// Released right after this returns; the test acquires during
				// the backoff that follows.
				defer close(inBackoff)
			}
			if calls < 3 {
				return errReset
			}
			return nil
		})
		done <- err
	}()

	<-inBackoff
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	// The send has returned, but release runs just after it; give it a moment
	// without leaving the backoff window.
	var release Release
	var err error
	for {
		release, err = g.Acquire(ctx, "a.test:80", LaneNormal)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("concurrent acquire during the retry backoff failed: %v (slot held through backoff)", err)
	}
	release(Outcome{})

	if err := <-done; err != nil {
		t.Fatalf("Do: %v", err)
	}
}

// With every normal slot held, a priority acquire still gets the reserved slot;
// a normal acquire does not.
func TestAcquire_PriorityLaneUsesReservedHeadroom(t *testing.T) {
	g := New(Config{Hosts: newHosts(t, 2)})
	ctx := context.Background()

	r1, err := g.Acquire(ctx, "a.test:443", LaneNormal)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.Acquire(ctx, "a.test:443", LaneNormal)
	if err != nil {
		t.Fatal(err)
	}

	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := g.Acquire(short, "a.test:443", LaneNormal); err == nil {
		t.Fatal("a third normal acquire succeeded with MaxPerHost=2")
	}

	pr, err := g.Acquire(ctx, "a.test:443", LanePriority)
	if err != nil {
		t.Fatalf("priority acquire with all normal slots held: %v", err)
	}

	// The headroom is one slot: a second priority acquire waits for a release.
	got := make(chan error, 1)
	go func() {
		rel, err := g.Acquire(ctx, "a.test:443", LanePriority)
		if err == nil {
			rel(Outcome{})
		}
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("second priority acquire did not wait (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	r1(Outcome{})
	if err := <-got; err != nil {
		t.Fatalf("second priority acquire after a release: %v", err)
	}
	pr(Outcome{})
	r2(Outcome{})
}

// A cancelled ctx unblocks a waiting acquire, and a backoff.
func TestCancel(t *testing.T) {
	g := New(Config{Hosts: newHosts(t, 1)})
	hold, err := g.Acquire(context.Background(), "a.test:80", LaneNormal)
	if err != nil {
		t.Fatal(err)
	}
	defer hold(Outcome{})

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := g.Acquire(ctx, "a.test:80", LaneNormal)
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("acquire err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not unblock a waiting acquire")
	}

	g2 := New(Config{})
	ctx2, cancel2 := context.WithCancel(context.Background())
	start := time.Now()
	go func() { time.Sleep(50 * time.Millisecond); cancel2() }()
	attempts, err := g2.Do(ctx2, "a.test:80", LaneNormal, RetryPolicy{
		MaxRetries: 3,
		Retryable:  alwaysRetry,
		Backoff:    func(int) time.Duration { return 10 * time.Second },
	}, func(int, bool) error { return errReset })
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("Do = (%d, %v), want (1, context.Canceled)", attempts, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancel did not cut the backoff short")
	}
}

// A quarantined host is refused before a token or a slot is spent, and a retry
// refused that way reports the attempt's own error.
func TestAcquire_Quarantine(t *testing.T) {
	breaker := hosterrors.New(2, 100, nil)
	lim := rate.NewLimiter(rate.Every(time.Hour), 10)
	g := New(Config{Rate: lim, Breaker: breaker})

	attempts, err := g.Do(context.Background(), "Dead.test:80", LaneNormal, RetryPolicy{
		MaxRetries: 5,
		Retryable:  alwaysRetry,
		Backoff:    func(int) time.Duration { return time.Millisecond },
	}, func(int, bool) error { return errReset })
	if !errors.Is(err, errReset) || attempts != 2 {
		t.Fatalf("Do = (%d, %v), want (2, reset): the breaker opens after 2 attempts", attempts, err)
	}
	if !breaker.Quarantined("dead.test:80") {
		t.Fatal("breaker key must be the lower-cased host:port")
	}
	sent := g.Sent()
	tokens := lim.Tokens()
	if _, err := g.Acquire(context.Background(), "dead.test:80", LaneNormal); !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		t.Fatalf("acquire on a quarantined host: %v", err)
	}
	if g.Sent() != sent || lim.Tokens() < tokens-0.01 {
		t.Fatal("a refused acquire spent a token or counted an attempt")
	}
}

// Views share the scan-wide counter; a phase counter sees only its view.
func TestViewsShareCounter(t *testing.T) {
	g := New(Config{})
	var phase atomic.Int64
	disc := g.WithRate(rate.NewLimiter(rate.Inf, 1)).WithPhaseCounter(&phase)

	for i := 0; i < 3; i++ {
		rel, err := disc.Acquire(context.Background(), "a.test:80", LaneNormal)
		if err != nil {
			t.Fatal(err)
		}
		rel(Outcome{})
	}
	disc.Count(2)
	rel, _ := g.Acquire(context.Background(), "a.test:80", LaneNormal)
	rel(Outcome{})
	if err := g.Token(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := g.Sent(); got != 7 {
		t.Fatalf("scan-wide Sent = %d, want 7", got)
	}
	if got := phase.Load(); got != 5 {
		t.Fatalf("phase counter = %d, want 5", got)
	}
}

func TestNilGateAdmits(t *testing.T) {
	var g *Gate
	rel, err := g.Acquire(context.Background(), "a.test:80", LanePriority)
	if err != nil {
		t.Fatal(err)
	}
	rel(Outcome{Err: errReset})
	if g.Sent() != 0 || g.Token(context.Background()) != nil {
		t.Fatal("nil gate must be a counting-free passthrough")
	}
}

// The RoundTripper counts each round trip, feeds the breaker, and reports a
// refusal as non-retryable while keeping its cause visible to errors.Is.
func TestRoundTripper(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	breaker := hosterrors.New(1, 100, nil)
	g := New(Config{Breaker: breaker})
	client := &http.Client{Transport: g.RoundTripper(http.DefaultTransport, LaneNormal)}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if g.Sent() != 1 || hits.Load() != 1 {
		t.Fatalf("Sent=%d hits=%d, want 1/1", g.Sent(), hits.Load())
	}

	u, _ := url.Parse(srv.URL)
	breaker.MarkFailed(HostPort(u), errors.New("connection refused"), false)
	_, err = client.Get(srv.URL)
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Retryable() {
		t.Fatalf("refusal err = %v, want a non-retryable *RefusedError", err)
	}
	if !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		t.Fatalf("refusal must unwrap to ErrUnresponsiveHost: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatal("a refused request reached the server")
	}
}

func TestHostPort(t *testing.T) {
	for raw, want := range map[string]string{
		"http://a.test/x":      "a.test:80",
		"https://a.test/":      "a.test:443",
		"https://a.test:8443/": "a.test:8443",
		"http://[::1]:8080/":   "[::1]:8080",
		"http:///no-host/path": "",
	} {
		u, _ := url.Parse(raw)
		if got := HostPort(u); got != want {
			t.Errorf("HostPort(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestDefaultBackoff(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i, w := range want {
		if got := DefaultBackoff(i); got != w {
			t.Errorf("DefaultBackoff(%d) = %v, want %v", i, got, w)
		}
	}
}

func TestInventory(t *testing.T) {
	all := Inventory(nil)
	if len(all.Exempt) != len(exemptPaths) || len(all.Gated) != len(gatedPaths) {
		t.Fatalf("nil phase list must include every path: %+v", all)
	}

	only := Inventory([]string{"dynamic-assessment"})
	has := func(path string) bool {
		for _, e := range only.Exempt {
			if e.Path == path {
				return true
			}
		}
		return false
	}
	if has("known-issue-scan") || has("spidering") {
		t.Fatal("exemptions for phases that do not run must be omitted")
	}
	if !has("http_request_smuggling.cl0") || !has("oast") {
		t.Fatal("dynamic-assessment exemptions missing")
	}
	for _, g := range only.Gated {
		if g == "discovery" || g == "port-sweep" {
			t.Fatalf("gated path %q listed for a scan that does not run it", g)
		}
	}
	for _, e := range all.Exempt {
		if e.Reason == "" {
			t.Fatalf("exemption %q has no reason", e.Path)
		}
	}
}

// AcquireHost must resolve exactly what Acquire does for the joined host:port.
func TestHostTargetMatchesParse(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
	}{
		{"a.test", 443}, {"A.Test", 80}, {"::1", 8443}, {"[::1]", 443}, {"", 80}, {"a]b", 1},
	} {
		want := parseTarget(net.JoinHostPort(tc.host, strconv.Itoa(tc.port)))
		if got := hostTarget(tc.host, tc.port); got != want {
			t.Errorf("hostTarget(%q, %d) = %+v, want %+v", tc.host, tc.port, got, want)
		}
	}
}
