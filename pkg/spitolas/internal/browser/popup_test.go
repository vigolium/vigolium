package browser

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// MISS-29a (real browser; skipped under -short): a popup opened by a click is
// listed with its URL and given time to load, so its own requests happen
// before the crawl closes it.
func TestPopupURLs(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	var assetHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><a id=go href="/popup" target="_blank">open</a></body></html>`))
	})
	mux.HandleFunc("/popup", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>popup<script src="/popup-asset.js"></script></body></html>`))
	})
	mux.HandleFunc("/popup-asset.js", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(400 * time.Millisecond)
		assetHits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("1"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg, err := config.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		t.Skipf("no usable browser in this environment: %v", err)
	}
	defer b.Close()
	page, err := b.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	if err := page.Navigate(srv.URL + "/"); err != nil {
		t.Fatal(err)
	}
	if err := page.Click("#go"); err != nil {
		t.Fatalf("click: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	urls := b.PopupURLs(page, 2*time.Second)
	found := false
	for _, u := range urls {
		if strings.HasSuffix(u, "/popup") {
			found = true
		}
	}
	if !found {
		t.Fatalf("popup not listed: %v", urls)
	}
	if assetHits.Load() == 0 {
		t.Error("the popup's own request did not complete before PopupURLs returned")
	}
}
