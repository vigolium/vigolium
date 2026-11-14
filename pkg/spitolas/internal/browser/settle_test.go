package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// ECON-9: fonts and media are always blocked, images only when third-party.
func TestBlockedResource(t *testing.T) {
	first := func(u string) bool { return u == "https://app.test/logo.png" }
	cases := []struct {
		rt   proto.NetworkResourceType
		url  string
		want bool
	}{
		{proto.NetworkResourceTypeFont, "https://app.test/a.woff2", true},
		{proto.NetworkResourceTypeMedia, "https://cdn.test/v.mp4", true},
		{proto.NetworkResourceTypeImage, "https://app.test/logo.png", false},
		{proto.NetworkResourceTypeImage, "https://ads.test/pixel.gif", true},
		{proto.NetworkResourceTypeScript, "https://cdn.test/app.js", false},
		{proto.NetworkResourceTypeXHR, "https://app.test/api", false},
	}
	for _, c := range cases {
		if got := blockedResource(c.rt, c.url, first); got != c.want {
			t.Errorf("blockedResource(%s, %s) = %v, want %v", c.rt, c.url, got, c.want)
		}
	}
}

// ECON-9 (real browser; skipped under -short): a page whose DOM never stops
// changing settles at the 3s cap instead of the 30s page timeout.
func TestWaitStable_CapsAtSettleCap(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id=t></div>
<script>setInterval(()=>{const d=document.createElement('p');d.textContent=Date.now();document.body.appendChild(d)},50)</script></body></html>`))
	}))
	defer srv.Close()
	cfg, err := config.New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Headless = true
	cfg.PageLoadTimeout = 30 * time.Second
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
	before := StableCapHits()
	start := time.Now()
	if err := page.WaitStable(500 * time.Millisecond); err != nil {
		t.Fatalf("WaitStable: %v (the cap counts as settled)", err)
	}
	if d := time.Since(start); d > 6*time.Second {
		t.Errorf("WaitStable took %v, want ~3s", d)
	}
	if StableCapHits() <= before {
		t.Errorf("cap hit not counted (returned after %v)", time.Since(start))
	}
}
