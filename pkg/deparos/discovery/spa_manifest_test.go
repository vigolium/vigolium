package discovery

import (
	"net/url"
	"testing"
)

func TestLooksLikeModernSPA(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"angular", `<app-root ng-version="17"></app-root>`, true},
		{"react CRA", `<div id="root"></div><script src="/static/js/main.abc.js"></script>`, true},
		{"nuxt", `<div id="__nuxt"></div><script>window.__NUXT__={}</script>`, true},
		{"next.js", `<script id="__NEXT_DATA__" type="application/json">{}</script>`, true},
		{"vue runtime", `<script>window.__VUE__=1</script>`, true},
		{"sveltekit", `<div id="svelte"></div><link href="/_app/immutable/x.js">`, true},
		{"generic sw registration", `<script>navigator.serviceWorker.register('/sw.js')</script>`, true},
		{"manifest link only", `<link rel="manifest" href="/manifest.webmanifest">`, true},
		{"plain server-rendered", `<html><body><h1>Blog</h1><p>hello</p></body></html>`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeModernSPA([]byte(tt.body)); got != tt.want {
				t.Errorf("looksLikeModernSPA = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSPAManifestCandidateURLs(t *testing.T) {
	origin := "https://app.example.com"

	t.Run("angular page gets generic + angular manifests", func(t *testing.T) {
		base := mustParseURL(t, origin+"/")
		body := `<html><head>` +
			`<script src="runtime.b634ae702caa8b86.js"></script>` +
			`<script src="polyfills.76a95cf66416d3a9.js"></script>` +
			`<link rel="manifest" href="manifest.webmanifest">` +
			`</head><body><app-root></app-root>` +
			`<script>navigator.serviceWorker.register('ngsw-worker.js')</script></body></html>`
		got := sortedURLStrings(spaManifestCandidateURLs(base, []byte(body)))
		for _, want := range []string{
			origin + "/ngsw.json",           // angular-specific
			origin + "/ngsw-worker.js",      // angular-specific
			origin + "/asset-manifest.json", // generic
			origin + "/sw.js",               // generic
			origin + "/firebase-messaging-sw.js",
			origin + "/manifest.webmanifest", // generic + link
		} {
			if !contains(got, want) {
				t.Errorf("missing %q in %v", want, got)
			}
		}
	})

	t.Run("react page gets generic incl asset-manifest, no angular ngsw", func(t *testing.T) {
		base := mustParseURL(t, origin+"/")
		body := `<html><body><div id="root"></div>` +
			`<script src="/static/js/main.abcd1234.js"></script></body></html>`
		got := sortedURLStrings(spaManifestCandidateURLs(base, []byte(body)))
		if !contains(got, origin+"/asset-manifest.json") {
			t.Errorf("react page should probe asset-manifest.json: %v", got)
		}
		if contains(got, origin+"/ngsw.json") {
			t.Errorf("non-angular page should NOT probe ngsw.json: %v", got)
		}
	})

	t.Run("nuxt page gets builds latest", func(t *testing.T) {
		base := mustParseURL(t, origin+"/")
		body := `<html><body><div id="__nuxt"></div><script>window.__NUXT__={}</script></body></html>`
		got := sortedURLStrings(spaManifestCandidateURLs(base, []byte(body)))
		if !contains(got, origin+"/_nuxt/builds/latest.json") {
			t.Errorf("nuxt page should probe /_nuxt/builds/latest.json: %v", got)
		}
	})

	t.Run("plain site yields nothing", func(t *testing.T) {
		base := mustParseURL(t, origin+"/")
		if got := spaManifestCandidateURLs(base, []byte(`<html><body><h1>hi</h1></body></html>`)); got != nil {
			t.Errorf("plain site: got %v, want nil", sortedURLStrings(got))
		}
	})

	t.Run("nil base", func(t *testing.T) {
		if got := spaManifestCandidateURLs(nil, []byte(`<app-root>`)); got != nil {
			t.Errorf("nil base: got %v", sortedURLStrings(got))
		}
	})

	t.Run("sub-path register target keeps directory", func(t *testing.T) {
		base := mustParseURL(t, origin+"/app/")
		body := `<html><body><app-root></app-root>` +
			`<script>navigator.serviceWorker.register('ngsw-worker.js')</script></body></html>`
		got := sortedURLStrings(spaManifestCandidateURLs(base, []byte(body)))
		if !contains(got, origin+"/app/ngsw-worker.js") {
			t.Errorf("expected sub-path worker from register(), got %v", got)
		}
		if !contains(got, origin+"/ngsw.json") {
			t.Errorf("expected root ngsw.json fallback, got %v", got)
		}
	})
}

func TestParseCRAAssetManifest(t *testing.T) {
	base := mustParseURL(t, "https://app.example.com/asset-manifest.json")
	body := `{
		"files": {
			"main.css": "/static/css/main.073c9b0a.css",
			"main.js": "/static/js/main.5f0e3a1b.js",
			"static/js/453.8a1f.chunk.js": "/static/js/453.8a1f.chunk.js",
			"static/media/logo.svg": "/static/media/logo.5d5d.svg",
			"index.html": "/index.html"
		},
		"entrypoints": [
			"static/js/runtime-main.1d3f.js",
			"static/js/main.5f0e3a1b.js"
		]
	}`
	got := sortedURLStrings(parseCRAAssetManifest(base, []byte(body)))
	origin := "https://app.example.com"

	for _, want := range []string{
		origin + "/static/js/main.5f0e3a1b.js",
		origin + "/static/js/453.8a1f.chunk.js",
		origin + "/static/js/runtime-main.1d3f.js", // entrypoint, relative-resolved
	} {
		if !contains(got, want) {
			t.Errorf("missing chunk %q in %v", want, got)
		}
	}
	// Non-fetchable assets dropped (css, svg, html).
	for _, u := range got {
		if u == origin+"/static/css/main.073c9b0a.css" ||
			u == origin+"/static/media/logo.5d5d.svg" ||
			u == origin+"/index.html" {
			t.Errorf("non-fetchable asset leaked: %v", u)
		}
	}
	if got := parseCRAAssetManifest(base, []byte(`garbage`)); got != nil {
		t.Errorf("garbage CRA manifest: got %v", sortedURLStrings(got))
	}
}

func TestParseNuxt(t *testing.T) {
	base := mustParseURL(t, "https://app.example.com/_nuxt/builds/latest.json")

	latest := `{"id":"abc123XYZ_-","timestamp":1700000000000}`
	got := sortedURLStrings(parseNuxtLatest(base, []byte(latest)))
	if !contains(got, "https://app.example.com/_nuxt/builds/meta/abc123XYZ_-.json") {
		t.Errorf("nuxt latest should derive meta url, got %v", got)
	}

	// Traversal-style id must be rejected.
	if got := parseNuxtLatest(base, []byte(`{"id":"../../etc/passwd"}`)); got != nil {
		t.Errorf("malicious id should be rejected, got %v", sortedURLStrings(got))
	}
	if got := parseNuxtLatest(base, []byte(`{}`)); got != nil {
		t.Errorf("missing id: got %v", sortedURLStrings(got))
	}

	meta := `{"id":"abc","timestamp":1,"prerendered":["/","/about","/blog/hello-world"]}`
	routes := parseNuxtPrerendered([]byte(meta))
	if len(routes) != 3 || !contains(routes, "/about") || !contains(routes, "/blog/hello-world") {
		t.Errorf("prerendered routes wrong: %v", routes)
	}
	if got := parseNuxtPrerendered([]byte(`not json`)); got != nil {
		t.Errorf("garbage meta: got %v", got)
	}
}

func TestParseWorkboxPrecache(t *testing.T) {
	base := mustParseURL(t, "https://app.example.com/sw.js")

	// Both key orderings, quoted and unquoted keys, null + string revisions.
	body := `importScripts("workbox-sw.js");
	workbox.precaching.precacheAndRoute([
	  {"url":"/static/js/main.5f0e.js","revision":null},
	  {"url":"/static/js/2.chunk.8a1f.js","revision":"8a1f"},
	  {revision:"abc",url:"/index.html"},
	  {url:'/static/js/vendor.0c0c.js',revision:'0c0c'}
	]);
	self.addEventListener('fetch', () => {});`

	got := sortedURLStrings(parseWorkboxPrecache(base, []byte(body)))
	origin := "https://app.example.com"
	for _, want := range []string{
		origin + "/static/js/main.5f0e.js",
		origin + "/static/js/2.chunk.8a1f.js",
		origin + "/static/js/vendor.0c0c.js",
	} {
		if !contains(got, want) {
			t.Errorf("missing workbox chunk %q in %v", want, got)
		}
	}
	// /index.html is in the precache list but is non-fetchable → dropped.
	if contains(got, origin+"/index.html") {
		t.Errorf("non-fetchable index.html should be dropped: %v", got)
	}

	// A service worker with no precache list yields nothing.
	if got := parseWorkboxPrecache(base, []byte(`self.addEventListener('fetch',()=>{})`)); got != nil {
		t.Errorf("non-workbox sw: got %v", sortedURLStrings(got))
	}
}

func TestURLClassifiers(t *testing.T) {
	cra := mustParseURL(t, "https://x.com/asset-manifest.json")
	if !isCRAAssetManifest(cra) {
		t.Error("isCRAAssetManifest false negative")
	}
	if isCRAAssetManifest(mustParseURL(t, "https://x.com/manifest.json")) {
		t.Error("isCRAAssetManifest false positive on manifest.json")
	}
	if !isNuxtLatest(mustParseURL(t, "https://x.com/_nuxt/builds/latest.json")) {
		t.Error("isNuxtLatest false negative")
	}
	if !isNuxtMeta(mustParseURL(t, "https://x.com/_nuxt/builds/meta/abc.json")) {
		t.Error("isNuxtMeta false negative")
	}
	if isNuxtMeta(mustParseURL(t, "https://x.com/_nuxt/builds/latest.json")) {
		t.Error("isNuxtMeta false positive on latest.json")
	}

	for _, sw := range []string{
		"https://x.com/sw.js", "https://x.com/service-worker.js",
		"https://x.com/ngsw-worker.js", "https://x.com/firebase-messaging-sw.js",
		"https://x.com/assets/workbox-abc.js",
	} {
		if !looksLikeServiceWorkerURL(mustParseURL(t, sw)) {
			t.Errorf("looksLikeServiceWorkerURL false negative for %q", sw)
		}
	}
	for _, notSW := range []string{
		"https://x.com/main.abc.js", "https://x.com/answers.js", "https://x.com/vendor.js",
	} {
		if looksLikeServiceWorkerURL(mustParseURL(t, notSW)) {
			t.Errorf("looksLikeServiceWorkerURL false positive for %q", notSW)
		}
	}
}

func TestHarvestSPAManifestDispatch(t *testing.T) {
	var queued []*url.URL
	var observed []string
	cb := &Callbacks{
		QueueJSFetch:    func(urls []*url.URL) { queued = append(queued, urls...) },
		AddObservedPath: func(p string) { observed = append(observed, p) },
	}

	// CRA asset-manifest.json → queued chunks.
	harvestSPAManifest(
		mustParseURL(t, "https://x.com/asset-manifest.json"),
		[]byte(`{"files":{"main.js":"/static/js/main.abc.js"},"entrypoints":["static/js/main.abc.js"]}`),
		cb,
	)
	if len(queued) == 0 || !contains(sortedURLStrings(queued), "https://x.com/static/js/main.abc.js") {
		t.Errorf("CRA dispatch did not queue chunk: %v", sortedURLStrings(queued))
	}

	// Nuxt meta → observed routes.
	harvestSPAManifest(
		mustParseURL(t, "https://x.com/_nuxt/builds/meta/abc.json"),
		[]byte(`{"prerendered":["/about","/contact"]}`),
		cb,
	)
	if !contains(observed, "/about") || !contains(observed, "/contact") {
		t.Errorf("Nuxt meta dispatch did not observe routes: %v", observed)
	}

	// Plain JS (not a manifest) → nothing.
	before := len(queued)
	harvestSPAManifest(
		mustParseURL(t, "https://x.com/main.abc.js"),
		[]byte(`console.log("hello")`),
		cb,
	)
	if len(queued) != before {
		t.Errorf("plain JS should not queue anything")
	}
}
