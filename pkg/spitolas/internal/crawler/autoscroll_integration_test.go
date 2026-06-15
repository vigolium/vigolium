//go:build integration

package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestCrawlAutoScrollTriggersLazyContent covers the "action on the page, load more
// content" case: a content landing requests data/assets only as sections scroll
// into view (IntersectionObserver / scroll-triggered fetches). A static headless
// visit that never scrolls misses them; the auto-scroll step must drive the page
// far enough that the lazy section's fetch (/api/lazy-section) is made and the
// network capture records it.
func TestCrawlAutoScrollTriggersLazyContent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// A tall page whose footer section fetches its data only when it scrolls
		// into view (IntersectionObserver) — i.e. below the initial viewport.
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<div style="height:4000px">hero</div>
			<div id="lazy">loading…</div>
			<script>
				const t = document.getElementById('lazy');
				const io = new IntersectionObserver((entries) => {
					for (const e of entries) {
						if (e.isIntersecting) {
							io.disconnect();
							fetch('/api/lazy-section?loaded=1').then(r => r.text()).then(x => { t.textContent = x; });
						}
					}
				});
				io.observe(t);
			</script>
		</body></html>`))
	})
	mux.HandleFunc("/api/lazy-section", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg, err := config.New(server.URL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 0
	cfg.MaxDuration = 60 * time.Second
	cfg.SPASettleTimeout = 5 * time.Second // AutoScroll on by default

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	rec := &recordingWriter{}
	c.SetWriter(rec)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := c.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !rec.sawContaining("/api/lazy-section") {
		t.Errorf("the below-the-fold lazy section's fetch was not captured — auto-scroll did not trigger it")
	}
}

// TestCrawlAutoScrollDisabledMissesLazyContent is the control: with AutoScroll
// off, the below-the-fold lazy fetch is NOT triggered, proving the capture in the
// test above is due to scrolling and not something else.
func TestCrawlAutoScrollDisabledMissesLazyContent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<div style="height:4000px">hero</div>
			<div id="lazy">loading…</div>
			<script>
				const t = document.getElementById('lazy');
				const io = new IntersectionObserver((entries) => {
					for (const e of entries) {
						if (e.isIntersecting) { io.disconnect(); fetch('/api/lazy-section?loaded=1'); }
					}
				});
				io.observe(t);
			</script>
		</body></html>`))
	})
	mux.HandleFunc("/api/lazy-section", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg, _ := config.New(server.URL)
	cfg.Headless = true
	cfg.MaxStates = 0
	cfg.MaxDepth = 0
	cfg.MaxDuration = 60 * time.Second
	cfg.SPASettleTimeout = 5 * time.Second
	cfg.AutoScroll = false // control: no scrolling

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	rec := &recordingWriter{}
	c.SetWriter(rec)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := c.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if rec.sawContaining("/api/lazy-section") {
		t.Errorf("lazy section fetched without scrolling — the test does not actually exercise auto-scroll")
	}
}
