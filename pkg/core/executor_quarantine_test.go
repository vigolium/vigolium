package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

type quarantineClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *quarantineClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *quarantineClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newQuarantineCache(clock *quarantineClock) *hosterrors.Cache {
	return hosterrors.NewWithConfig(hosterrors.Config{
		MaxHostError: 1,
		Cooldown:     30 * time.Second,
		Now:          clock.Now,
	})
}

var errQuarantineRefused = errors.New("dial tcp: connect: connection refused")

// sendItem's pre-filter is read-only: however many items it looks at after the
// cooldown, the half-open probe is still there for the requester's Admit.
func TestSendItemNeverConsumesProbe(t *testing.T) {
	t.Parallel()
	clock := &quarantineClock{t: time.Unix(1_700_000_000, 0)}
	cache := newQuarantineCache(clock)
	e, _ := newTestExecutor(ExecutorConfig{Services: &services.Services{HostErrors: cache}}, nil)

	item, rr := makeTestItem("dead.example.com", "/", "x")
	key := httpmsg.HostPortKey(rr)
	cache.MarkFailed(key, errQuarantineRefused, false)

	itemCh := make(chan *work.WorkItem, 256)
	// During the cooldown the item is dropped, with a count.
	if !e.sendItem(context.Background(), item, itemCh) || len(itemCh) != 0 {
		t.Fatal("item for a quarantined host should be dropped, not dispatched")
	}

	clock.Advance(31 * time.Second)
	for i := range 100 {
		it, _ := makeTestItem("dead.example.com", fmt.Sprintf("/p%d", i), "x")
		e.sendItem(context.Background(), it, itemCh)
	}
	if len(itemCh) != 100 {
		t.Fatalf("after the cooldown items should be dispatched; got %d of 100", len(itemCh))
	}
	if got := cache.State(key); got != hosterrors.StateOpen {
		t.Fatalf("sendItem changed breaker state to %s; it must stay open until Admit", got)
	}
	if ok, _ := cache.Admit(key); !ok {
		t.Fatal("the probe was consumed by the executor's pre-filter")
	}

	rep := e.Report()
	if rep.SkippedQuarantined != 1 {
		t.Errorf("SkippedQuarantined = %d, want 1", rep.SkippedQuarantined)
	}
	if len(rep.QuarantinedHosts) != 1 || rep.QuarantinedHosts[0].Host != key || rep.QuarantinedHosts[0].Items != 1 {
		t.Errorf("QuarantinedHosts = %+v, want one entry for %s with 1 item", rep.QuarantinedHosts, key)
	}
	if rep.QuarantinedHosts[0].Class != http.TransportErrRefused {
		t.Errorf("Class = %q, want %q", rep.QuarantinedHosts[0].Class, http.TransportErrRefused)
	}
	if !rep.Clean() {
		t.Error("a quarantine skip is the target's doing; Clean must not flag it")
	}
}

// A run's report counts every item dropped for a quarantined host, per host,
// whatever the method; a second run reports only its own share.
func TestExecuteReportsQuarantineSkips(t *testing.T) {
	t.Parallel()
	clock := &quarantineClock{t: time.Unix(1_700_000_000, 0)}
	cache := newQuarantineCache(clock)
	e, _ := newTestExecutor(ExecutorConfig{Workers: 1, Services: &services.Services{HostErrors: cache}}, nil)
	e.pool.feedbackCh = make(chan *work.WorkItem, 16)
	e.scanCtx = &modules.ScanContext{}

	_, dead := makeTestItem("dead.example.com", "/", "x")
	cache.MarkFailed(httpmsg.HostPortKey(dead), errQuarantineRefused, false)

	var items []*work.WorkItem
	for i := range 3 {
		it, _ := makeTestItem("dead.example.com", fmt.Sprintf("/g%d", i), "x")
		items = append(items, it)
	}
	post := work.NewWithModules(httpmsg.NewHttpRequestResponse(dead.Request().WithMethod("POST"), dead.Response()), nil)
	items = append(items, post)
	live, _ := makeTestItem("live.example.com", "/", "x")
	items = append(items, live)
	e.source = &sliceSource{items: items}

	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rep := e.Report()
	if rep.SkippedQuarantined != 4 {
		t.Errorf("SkippedQuarantined = %d, want 4 (3 GET + 1 POST)", rep.SkippedQuarantined)
	}
	if len(rep.QuarantinedHosts) != 1 || rep.QuarantinedHosts[0].State != "open" {
		t.Errorf("QuarantinedHosts = %+v", rep.QuarantinedHosts)
	}

	e.source = &sliceSource{}
	if _, err := e.Execute(context.Background()); err != nil {
		t.Fatalf("second Execute: %v", err)
	}
	if rep := e.Report(); rep.SkippedQuarantined != 0 || rep.QuarantinedHosts != nil {
		t.Errorf("second run inherited quarantine skips: %+v", rep)
	}
}
