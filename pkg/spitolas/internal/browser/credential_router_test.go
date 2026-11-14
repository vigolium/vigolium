package browser

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

func TestMergeFetchHeaders(t *testing.T) {
	orig := proto.NetworkHeaders{"accept": gson.New("*/*"), "authorization": gson.New("stale")}
	got := mergeFetchHeaders(orig, map[string]string{"Authorization": "Bearer t"})
	m := map[string]string{}
	for _, e := range got {
		m[strings.ToLower(e.Name)] = e.Value
	}
	if m["authorization"] != "Bearer t" || m["accept"] != "*/*" || len(got) != 2 {
		t.Errorf("merged = %v", m)
	}
	if p := CredentialHostPatterns("App.Test"); len(p) != 4 || p[0] != "*://app.test/*" {
		t.Errorf("patterns = %v", p)
	}
}

// SAFE-3 (real browser; skipped under -short or without one): the document
// request carries the credential header, a third-party script it loads does
// not.
func TestCredentialRouter_ThirdPartyGetsNoHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("launches a real browser")
	}
	var mu sync.Mutex
	got := map[string]string{}
	record := func(key string, r *http.Request) {
		mu.Lock()
		got[key] = r.Header.Get("X-Api-Key")
		mu.Unlock()
	}
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("third", r)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("window.__tp = 1;"))
	}))
	defer third.Close()
	thirdURL := strings.Replace(third.URL, "127.0.0.1", "localhost", 1)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record("doc", r)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>app<script src="` + thirdURL + `/tp.js"></script></body></html>`))
	}))
	defer app.Close()

	cfg, err := config.New(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		t.Skipf("no usable browser in this environment: %v", err)
	}
	defer func() { _ = b.Close() }()
	page, err := b.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	allow := func(raw string) bool {
		u, perr := url.Parse(raw)
		return perr == nil && u.Hostname() == "127.0.0.1"
	}
	if err := page.InstallCredentialRouter(map[string]string{"X-Api-Key": "secret"}, allow, nil, nil); err != nil {
		t.Fatalf("InstallCredentialRouter: %v", err)
	}
	if err := page.Navigate(app.URL + "/"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		_, sawThird := got["third"]
		mu.Unlock()
		if sawThird {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if got["doc"] != "secret" {
		t.Errorf("document request X-Api-Key = %q, want secret", got["doc"])
	}
	v, sawThird := got["third"]
	if !sawThird {
		t.Fatal("third-party script was never requested")
	}
	if v != "" {
		t.Errorf("third-party request carried X-Api-Key = %q", v)
	}
}
