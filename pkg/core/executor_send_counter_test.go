package core

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/stats"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
)

// MEAS-4: every wire request a module call sends is attributed to that module
// in ModuleStatsSnapshot.Requests, so request budgets can be measured and
// regressions caught.
func TestRunActiveWithTimeout_CountsModuleRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	reqClient := newAbandonTestRequester(t)
	e := &Executor{
		cfg:           ExecutorConfig{ActiveModuleTimeout: 10 * time.Second},
		moduleMetrics: &stats.ModuleMetrics{},
	}

	item, err := httpmsg.GetRawRequestFromURL(srv.URL + "/?q=1")
	if err != nil {
		t.Fatal(err)
	}

	const sends = 3
	for i := range 2 { // two calls of the same module accumulate
		_, completed := e.runActiveWithTimeout(context.Background(),
			func(_ context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
				for range sends {
					chain, _, err := client.Execute(item, http.Options{NoClustering: true})
					if err != nil {
						return nil, err
					}
					chain.Close()
				}
				return nil, nil
			},
			&fakeActiveModule{id: "counted"}, item, reqClient, func() {}, 0)
		if !completed {
			t.Fatalf("call %d did not complete", i)
		}
	}

	snap := e.moduleMetrics.Snapshot()["counted"]
	if snap.Requests != 2*sends {
		t.Fatalf("Requests = %d, want %d (server saw %d)", snap.Requests, 2*sends, hits.Load())
	}
	if snap.Invocations != 2 {
		t.Fatalf("Invocations = %d, want 2", snap.Invocations)
	}
}

// A view's counter is private to that view: the parent requester and sibling
// views keep their own tallies.
func TestRequesterWithSendCounter_IsPerView(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	base := newAbandonTestRequester(t)
	if base.WithSendCounter(nil) != base {
		t.Fatal("WithSendCounter(nil) must return the receiver")
	}
	var a, b atomic.Int64
	va := base.WithSendCounter(&a)
	_ = base.WithSendCounter(&b) // a sibling view that never sends

	item, err := httpmsg.GetRawRequestFromURL(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		chain, _, err := va.Execute(item, http.Options{NoClustering: true})
		if err != nil {
			t.Fatal(err)
		}
		chain.Close()
	}
	chain, _, err := base.Execute(item, http.Options{NoClustering: true})
	if err != nil {
		t.Fatal(err)
	}
	chain.Close()

	if a.Load() != 2 || b.Load() != 0 {
		t.Fatalf("counters a=%d b=%d, want 2 and 0", a.Load(), b.Load())
	}
}
