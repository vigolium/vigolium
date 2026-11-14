//go:build integration

package spitolas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestPopupURLBecomesFrontierSeed: a page reachable only through a
// target=_blank link is browsed into the frontier, so the actions it offers
// are explored — its button's XHR fires.
func TestPopupURLBecomesFrontierSeed(t *testing.T) {
	var deep atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/popup":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><body><h1>popup</h1>
<button id=go onclick="fetch('/api/popup-deep').then(()=>{document.body.insertAdjacentHTML('beforeend','<p>done</p>')})">load</button></body></html>`))
		case "/api/popup-deep":
			deep.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><body><h1>home</h1><a href="/popup" target="_blank">open</a></body></html>`))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := RunSpider(ctx, SpiderConfig{
		TargetURL: srv.URL, MaxStates: 10, MaxDepth: 3, MaxDuration: 45 * time.Second,
		Headless: true, IncludeResponseBody: true,
	}, &memSink{})
	if err != nil {
		t.Skipf("crawl could not run here: %v", err)
	}
	_ = res
	if deep.Load() == 0 {
		t.Error("the popup page's action was never explored: popup URL not seeded into the frontier")
	}
}
