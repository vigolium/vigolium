//go:build integration

package crawler

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// lazyFrameSite serves a home page whose only frame is a below-the-fold
// loading="lazy" iframe pointing at /lazy/captcha?source=weuci. A headless
// browser does not scroll, so it never loads the lazy frame on its own — the
// frame URL is only requested if iframe-source priming reads it out of the DOM
// and fetches it. The handler records every requested URI so the test can assert
// whether the frame was hit.
func lazyFrameSite() (*testutil.TestServer, func(string) bool) {
	var mu sync.Mutex
	hits := map[string]bool{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.RequestURI()] = true
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/lazy/captcha" {
			_, _ = w.Write([]byte("<!doctype html><html><body>captcha source=" +
				r.URL.Query().Get("source") + "</body></html>"))
			return
		}
		// A tall spacer pushes the lazy iframe well below any headless viewport so
		// Chromium defers its load. The frame is same-origin and its src appears
		// only here (no anchor links to it).
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<h1>home</h1>
			<div style="height:12000px"></div>
			<iframe loading="lazy" src="/lazy/captcha?source=weuci" width="200" height="200"></iframe>
		</body></html>`))
	})

	ts := testutil.NewTestServerWithHandler(mux)
	wasHit := func(uri string) bool {
		mu.Lock()
		defer mu.Unlock()
		return hits[uri]
	}
	return ts, wasHit
}

func runLazyFrameCrawl(t *testing.T, primingOn bool) func(string) bool {
	t.Helper()
	server, wasHit := lazyFrameSite()
	defer server.Close()

	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.Silent = true
	cfg.MaxStates = 1
	cfg.MaxDuration = 20 * time.Second
	cfg.IframePriming = primingOn

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := c.Run(ctx); err != nil {
		t.Fatalf("crawl run: %v", err)
	}
	return wasHit
}

// TestIframePrimingFetchesLazyFrame is the positive case: with priming on
// (default), the below-the-fold lazy iframe — which the headless browser never
// loads itself — is read from the DOM and fetched, so its URL (with the reflected
// source=weuci query) reaches the server and would be recorded for scanning.
func TestIframePrimingFetchesLazyFrame(t *testing.T) {
	wasHit := runLazyFrameCrawl(t, true)
	if !wasHit("/lazy/captcha?source=weuci") {
		t.Fatal("iframe priming should have fetched the lazy frame /lazy/captcha?source=weuci, but it was never requested")
	}
}

// TestIframePrimingDisabledMissesLazyFrame is the negative control: with priming
// off, nothing fetches the deferred lazy frame, so the server never sees it —
// demonstrating the gap priming closes. (If this ever fails, the headless build
// is eagerly loading lazy frames; the positive test still holds.)
func TestIframePrimingDisabledMissesLazyFrame(t *testing.T) {
	wasHit := runLazyFrameCrawl(t, false)
	if wasHit("/lazy/captcha?source=weuci") {
		t.Skip("headless build eagerly loaded the lazy frame; priming gap not observable here")
	}
}
