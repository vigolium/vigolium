package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"golang.org/x/time/rate"
)

// Concurrent takers at the boundary: exactly max succeed, the rest are refused
// with a global BudgetError, and the global hook fires once.
func TestBudget_ConcurrentTake(t *testing.T) {
	const limit, workers, each = 100, 16, 25
	b := NewBudget(limit, 0)
	var fired atomic.Int32
	b.SetHooks(BudgetHooks{Global: func(*BudgetError) { fired.Add(1) }})
	g := New(Config{}).WithBudget(b)

	var ok, refused atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				release, err := g.Acquire(context.Background(), "a.test:80", LaneNormal)
				if err != nil {
					var be *BudgetError
					if !errors.As(err, &be) || be.Kind != BudgetGlobal {
						t.Errorf("Acquire error = %v, want a global BudgetError", err)
					}
					refused.Add(1)
					continue
				}
				release(Outcome{})
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != limit {
		t.Fatalf("admitted %d, want exactly %d", ok.Load(), limit)
	}
	if refused.Load() != workers*each-limit {
		t.Fatalf("refused %d, want %d", refused.Load(), workers*each-limit)
	}
	if g.Sent() != limit || b.Used() != limit {
		t.Fatalf("Sent = %d, Used = %d, want %d", g.Sent(), b.Used(), limit)
	}
	if fired.Load() != 1 || !b.Exhausted() {
		t.Fatalf("global hook fired %d times (exhausted=%v), want once", fired.Load(), b.Exhausted())
	}
}

// Per-host limits are per host: one host running out leaves another untouched,
// and the host hook fires once per host.
func TestBudget_PerHostIsolation(t *testing.T) {
	b := NewBudget(0, 2)
	var hosts []string
	var mu sync.Mutex
	b.SetHooks(BudgetHooks{Host: func(h string) { mu.Lock(); hosts = append(hosts, h); mu.Unlock() }})
	g := New(Config{}).WithBudget(b)

	acquire := func(hp string) error {
		release, err := g.Acquire(context.Background(), hp, LaneNormal)
		if err == nil {
			release(Outcome{})
		}
		return err
	}
	for i := range 2 {
		if err := acquire("A.test:443"); err != nil {
			t.Fatalf("a.test attempt %d refused: %v", i, err)
		}
	}
	for range 3 {
		err := acquire("a.test:8443") // same host, other port: same budget
		var be *BudgetError
		if !errors.As(err, &be) || be.Kind != BudgetHost || be.Host != "a.test" {
			t.Fatalf("over-budget attempt = %v, want host BudgetError for a.test", err)
		}
	}
	if err := acquire("b.test:443"); err != nil {
		t.Fatalf("b.test refused by a.test's budget: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "a.test" {
		t.Fatalf("host hook calls = %v, want [a.test] once", hosts)
	}
	if got := b.ExhaustedHosts(); len(got) != 1 || got[0] != "a.test" {
		t.Fatalf("ExhaustedHosts = %v", got)
	}
	if b.Exhausted() {
		t.Fatal("a per-host limit marked the scan-wide budget exhausted")
	}
}

// A request over budget is never dialed: the httptest server sees exactly the
// budgeted number of requests through a gated RoundTripper.
func TestBudget_OverBudgetNeverDialed(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	g := New(Config{}).WithBudget(NewBudget(3, 0))
	client := &http.Client{Transport: g.RoundTripper(nil, LaneNormal)}
	var refused int
	for range 5 {
		resp, err := client.Get(srv.URL)
		if err != nil {
			if !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("unexpected error: %v", err)
			}
			refused++
			continue
		}
		_ = resp.Body.Close()
	}
	if hits.Load() != 3 || refused != 2 {
		t.Fatalf("server hits = %d, refused = %d; want 3 and 2", hits.Load(), refused)
	}
}

// The budget refuses before the rate wait: an exhausted budget never spends a
// token (the limiter here has none to give, so waiting would block).
func TestBudget_RefusesBeforeRateWait(t *testing.T) {
	lim := rate.NewLimiter(rate.Every(time.Hour), 1)
	g := New(Config{Rate: lim}).WithBudget(NewBudget(1, 0))
	release, err := g.Acquire(context.Background(), "a.test:80", LaneNormal)
	if err != nil {
		t.Fatal(err)
	}
	release(Outcome{})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := g.Acquire(ctx, "a.test:80", LaneNormal); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("second Acquire = %v, want ErrBudgetExhausted without waiting", err)
	}
}

// An attempt the breaker refuses costs no budget.
func TestBudget_BreakerRefusalCostsNothing(t *testing.T) {
	cache := hosterrors.New(1, hosterrors.DefaultMaxHostsCount, nil)
	b := NewBudget(10, 0)
	g := New(Config{Breaker: cache}).WithBudget(b)
	cache.MarkFailed("a.test:80", errors.New("connection refused"), false)
	if _, err := g.Acquire(context.Background(), "a.test:80", LaneNormal); err == nil {
		t.Fatal("quarantined host admitted")
	}
	if b.Used() != 0 {
		t.Fatalf("Used = %d after a refused attempt, want 0", b.Used())
	}
}

// Views share the budget: a WithRate/With view is held to the root's limit.
func TestBudget_SharedByViews(t *testing.T) {
	root := New(Config{}).WithBudget(NewBudget(2, 0))
	views := []*Gate{root.WithRate(nil), root.With(Config{}), root.WithPhaseCounter(&atomic.Int64{})}
	var admitted int
	for _, v := range views {
		if release, err := v.Acquire(context.Background(), "a.test:80", LaneNormal); err == nil {
			release(Outcome{})
			admitted++
		}
	}
	if admitted != 2 {
		t.Fatalf("views admitted %d, want 2 (one shared budget)", admitted)
	}
}

// Token (a redirect hop) and Count (a bare dial) are charged to the scan-wide
// limit; Token is refused once it is spent, Count never is.
func TestBudget_TokenAndCount(t *testing.T) {
	b := NewBudget(2, 1)
	g := New(Config{}).WithBudget(b)
	g.Count(1)
	if err := g.Token(context.Background()); err != nil {
		t.Fatalf("Token within budget: %v", err)
	}
	if err := g.Token(context.Background()); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("Token over budget = %v", err)
	}
	g.Count(1) // already on the wire: counted, not refused
	if b.Used() != 3 {
		t.Fatalf("Used = %d, want 3", b.Used())
	}
}

// Soft enforcement: tracked (ungated) traffic counts toward the scan-wide
// limit and the watcher fires the global hook once it goes past it.
func TestBudget_TrackedCountersSoftEnforcement(t *testing.T) {
	b := NewBudget(10, 0)
	fired := make(chan *BudgetError, 1)
	b.SetHooks(BudgetHooks{Global: func(e *BudgetError) { fired <- e }})

	var browser atomic.Int64
	browser.Store(100) // value before tracking does not count
	b.Track(browser.Load)
	stop := b.Watch(context.Background(), 5*time.Millisecond)
	defer stop()

	browser.Add(6)
	time.Sleep(30 * time.Millisecond)
	if b.Used() != 6 || b.Exhausted() {
		t.Fatalf("Used = %d exhausted = %v, want 6 and not exhausted", b.Used(), b.Exhausted())
	}
	// Gated traffic sees the sampled share: only 4 more fit.
	g := New(Config{}).WithBudget(b)
	for range 4 {
		release, err := g.Acquire(context.Background(), "a.test:80", LaneNormal)
		if err != nil {
			t.Fatalf("gated attempt refused early: %v", err)
		}
		release(Outcome{})
	}
	if b.Used() != 10 {
		t.Fatalf("Used = %d, want 10", b.Used())
	}
	if b.Exhausted() {
		t.Fatal("reaching the limit exactly is not exhaustion")
	}

	// A new tracked engine that goes past the limit trips the watcher.
	var crawl atomic.Int64
	b.Track(crawl.Load)
	crawl.Add(1)
	select {
	case e := <-fired:
		if e.Kind != BudgetGlobal {
			t.Fatalf("hook kind = %s", e.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not fire the global hook")
	}
}

// BudgetCause finds the budget error a parent context was cancelled with, from
// a derived context too; any other cancellation is not a budget stop.
func TestBudgetCause(t *testing.T) {
	parent, cancel := context.WithCancelCause(context.Background())
	child, childCancel := context.WithTimeout(parent, time.Hour)
	defer childCancel()
	if BudgetCause(child) != nil {
		t.Fatal("live context reported a budget cause")
	}
	cancel(&BudgetError{Kind: BudgetGlobal, Limit: 5})
	if be := BudgetCause(child); be == nil || be.Limit != 5 {
		t.Fatalf("BudgetCause(child) = %v", be)
	}
	plain, plainCancel := context.WithCancel(context.Background())
	plainCancel()
	if BudgetCause(plain) != nil {
		t.Fatal("plain cancellation reported as a budget stop")
	}
}

func TestNewBudgetOff(t *testing.T) {
	if NewBudget(0, 0) != nil {
		t.Fatal("NewBudget(0,0) should be nil (unlimited)")
	}
	var b *Budget
	if err := b.take(b.forHost("x")); err != nil || b.Exhausted() || b.Used() != 0 {
		t.Fatal("nil budget must admit everything")
	}
}

func TestRequestCapEnforcement(t *testing.T) {
	got := RequestCapEnforcement([]string{"discovery", "spidering", "known-issue-scan", "dynamic-assessment", "external-harvest"})
	want := map[string]string{
		"discovery":          EnforcementHard,
		"spidering":          EnforcementSoft,
		"known-issue-scan":   EnforcementSoft, // MISS-35: nuclei requests are counted via its progress hooks
		"dynamic-assessment": EnforcementPartial,
		"external-harvest":   EnforcementHard,
	}
	for phase, w := range want {
		if got[phase] != w {
			t.Errorf("%s = %q, want %q", phase, got[phase], w)
		}
	}
}
