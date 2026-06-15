//go:build integration

package crawler

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/testutil"
)

// hitRecorder wraps a mux and records every requested URI (path+query).
func hitRecorder(mux http.Handler) (http.Handler, func(string) bool) {
	var mu sync.Mutex
	hits := map[string]bool{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.RequestURI()] = true
		mu.Unlock()
		mux.ServeHTTP(w, r)
	})
	was := func(uri string) bool {
		mu.Lock()
		defer mu.Unlock()
		return hits[uri]
	}
	return h, was
}

// crawlIndex runs an index-only crawl (MaxStates=1) of the server so iframe
// priming runs on the landing page. Index-level keeps it deterministic — it does
// not depend on the state machine progressing (which is environment-sensitive).
func crawlIndex(t *testing.T, server *testutil.TestServer) {
	t.Helper()
	cfg, err := config.New(server.URL())
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	cfg.Silent = true
	cfg.MaxStates = 1
	cfg.MaxDuration = 20 * time.Second

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New crawler: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := c.Run(ctx); err != nil {
		t.Fatalf("crawl run: %v", err)
	}
}

// belowFoldLazyIframe returns a lazy, far-below-the-fold iframe — the headless
// browser never scrolls to it, so it loads ONLY if priming reads the src and
// fetches it. This isolates "priming did it" from the browser's own iframe load.
func belowFoldLazyIframe(src string) string {
	return `<div style="height:12000px"></div>` +
		`<iframe loading="lazy" src="` + src + `" width="100" height="100"></iframe>`
}

// TestIframePrimingNextjsDynamicInjection — a Next.js/React style app that mounts
// the frame client-side after hydration (setTimeout), and lazily. The served HTML
// never contains the URL; only reading the rendered DOM after settle finds it.
func TestIframePrimingNextjsDynamicInjection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/_next/captcha" {
			_, _ = w.Write([]byte("<!doctype html><html><body>captcha " + r.URL.Query().Get("source") + "</body></html>"))
			return
		}
		// React-ish shell: the frame is appended after "hydration", and is lazy +
		// below-fold so the browser itself won't load it.
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<div id="__next"><h1>app</h1></div>
			<div style="height:12000px"></div>
			<script>
				setTimeout(function(){
					var f = document.createElement('iframe');
					f.loading = 'lazy';
					f.src = '/_next/captcha?source=weuci';
					document.body.appendChild(f);
				}, 150);
			</script>
		</body></html>`))
	})

	rec, was := hitRecorder(mux)
	server := testutil.NewTestServerWithHandler(rec)
	defer server.Close()

	crawlIndex(t, server)
	if !was("/_next/captcha?source=weuci") {
		t.Fatal("priming should have fetched the hydration-injected lazy iframe /_next/captcha?source=weuci")
	}
}

// TestIframePrimingShadowDOM — a web component renders a lazy below-fold iframe
// inside its shadow root (a web-component design system / Stencil / Lit pattern). A plain
// document.querySelectorAll never sees it; only shadow-piercing discovery does.
func TestIframePrimingShadowDOM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/shadow/captcha" {
			_, _ = w.Write([]byte("<!doctype html><html><body>captcha " + r.URL.Query().Get("source") + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte(`<!doctype html><html><body>
			<h1>app</h1>
			<x-login></x-login>
			<script>
				class XLogin extends HTMLElement {
					connectedCallback() {
						const sr = this.attachShadow({mode: 'open'});
						sr.innerHTML =
							'<div style="height:12000px"></div>' +
							'<iframe loading="lazy" src="/shadow/captcha?source=weuci" width="80" height="80"></iframe>';
					}
				}
				customElements.define('x-login', XLogin);
			</script>
		</body></html>`))
	})

	rec, was := hitRecorder(mux)
	server := testutil.NewTestServerWithHandler(rec)
	defer server.Close()

	crawlIndex(t, server)
	if !was("/shadow/captcha?source=weuci") {
		t.Fatal("priming should have pierced the shadow root and fetched /shadow/captcha?source=weuci")
	}
}

// TestIframePrimingNestedSameOrigin — a same-origin parent frame loads normally;
// priming must recurse into its document and harvest the lazy frame nested inside.
func TestIframePrimingNestedSameOrigin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/frameA":
			_, _ = w.Write([]byte("<!doctype html><html><body>A" + belowFoldLazyIframe("/nested/deep?x=1") + "</body></html>"))
		case "/nested/deep":
			_, _ = w.Write([]byte("<!doctype html><html><body>deep</body></html>"))
		default:
			_, _ = w.Write([]byte(`<!doctype html><html><body><iframe src="/frameA" width="300" height="200"></iframe></body></html>`))
		}
	})

	rec, was := hitRecorder(mux)
	server := testutil.NewTestServerWithHandler(rec)
	defer server.Close()

	crawlIndex(t, server)
	if !was("/nested/deep?x=1") {
		t.Fatal("priming should have recursed into the same-origin parent frame and fetched /nested/deep?x=1")
	}
}

// TestIframePrimingTraditionalStaticIframeQuery — a classic server-rendered
// (PHP/JSP) page with a static iframe carrying a multi-param query. Priming must
// harvest it with the query string intact (the reflected-param case that matters
// for scanning).
func TestIframePrimingTraditionalStaticIframeQuery(t *testing.T) {
	const widget = "/widget.php?id=42&cat=news&token=abc"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/widget.php" {
			_, _ = w.Write([]byte("<!doctype html><html><body>widget id=" + r.URL.Query().Get("id") + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<!doctype html><html><body><h1>home</h1>" + belowFoldLazyIframe(widget) + "</body></html>"))
	})

	rec, was := hitRecorder(mux)
	server := testutil.NewTestServerWithHandler(rec)
	defer server.Close()

	crawlIndex(t, server)
	if !was(widget) {
		t.Fatalf("priming should have fetched the static iframe with its query intact: %s", widget)
	}
}

// TestIframePrimingSkipsCrossOrigin — a below-fold lazy iframe pointing at a
// DIFFERENT origin must never be fetched: the browser defers it (lazy/off-screen)
// and priming skips it (same-origin gate). The cross-origin server sees nothing.
func TestIframePrimingSkipsCrossOrigin(t *testing.T) {
	otherMux := http.NewServeMux()
	otherMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>evil</body></html>"))
	})
	otherRec, otherWas := hitRecorder(otherMux)
	other := testutil.NewTestServerWithHandler(otherRec)
	defer other.Close()

	crossOrigin := other.URL() + "/evil?x=1"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body><h1>home</h1>" + belowFoldLazyIframe(crossOrigin) + "</body></html>"))
	})
	rec, was := hitRecorder(mux)
	server := testutil.NewTestServerWithHandler(rec)
	defer server.Close()

	crawlIndex(t, server)

	if otherWas("/evil?x=1") {
		t.Fatal("priming must NOT fetch a cross-origin iframe src")
	}
	// Sanity: the main origin was actually crawled.
	if !was("/") {
		t.Fatal("expected the main page to have been requested")
	}
}

// TestIframePrimingFetchesManySameOrigin is a light cap/sanity check: several
// same-origin lazy frames are all harvested (well under IframeMaxAssets).
func TestIframePrimingFetchesManySameOrigin(t *testing.T) {
	const n = 5
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var body string
		body = "<!doctype html><html><body><h1>home</h1><div style=\"height:12000px\"></div>"
		for i := 0; i < n; i++ {
			body += fmt.Sprintf(`<iframe loading="lazy" src="/f%d?i=%d" width="50" height="50"></iframe>`, i, i)
		}
		body += "</body></html>"
		_, _ = w.Write([]byte(body))
	})
	rec, was := hitRecorder(mux)
	server := testutil.NewTestServerWithHandler(rec)
	defer server.Close()

	crawlIndex(t, server)
	for i := 0; i < n; i++ {
		uri := fmt.Sprintf("/f%d?i=%d", i, i)
		if !was(uri) {
			t.Errorf("same-origin lazy frame %s not primed", uri)
		}
	}
}
