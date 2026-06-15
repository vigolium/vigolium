package discovery

import (
	"net/url"
	"sort"
	"testing"
)

func sortedURLStrings(us []*url.URL) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = u.String()
	}
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func TestLooksLikeAngularApp(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "angular CLI shell with app-root + hashed bundles",
			body: `<html><head>` +
				`<script src="runtime.b634ae702caa8b86.js" type="module"></script>` +
				`<script src="polyfills.76a95cf66416d3a9.js" type="module"></script>` +
				`<script src="main.e2d7eff37dafe1be.js" type="module"></script>` +
				`<link rel="manifest" href="manifest.webmanifest"></head>` +
				`<body><app-root></app-root></body></html>`,
			want: true,
		},
		{
			name: "ng-version marker only",
			body: `<html><body><app-root ng-version="17.1.0"></app-root></body></html>`,
			want: true,
		},
		{
			name: "ngsw-worker registration only",
			body: `<html><body><script>navigator.serviceWorker.register('ngsw-worker.js')</script></body></html>`,
			want: true,
		},
		{
			name: "runtime + polyfills pair without app-root",
			body: `<html><head><script src="runtime.abc.js"></script><script src="polyfills.def.js"></script></head><body></body></html>`,
			want: true,
		},
		{
			name: "plain site is not angular",
			body: `<html><body><h1>Welcome</h1><script src="/static/app.js"></script></body></html>`,
			want: false,
		},
		{
			name: "lone main.js bundle is not enough",
			body: `<html><head><script src="main.1234.js"></script></head><body></body></html>`,
			want: false,
		},
		{
			name: "empty body",
			body: ``,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeAngularApp([]byte(tt.body)); got != tt.want {
				t.Errorf("looksLikeAngularApp = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNgswManifest(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"https://example.com/ngsw.json", true},
		{"https://example.com/app/ngsw.json", true},
		{"https://example.com/NGSW.JSON", true},
		{"https://example.com/ngsw-worker.js", false},
		{"https://example.com/manifest.webmanifest", false},
		{"https://example.com/ngsw.json.bak", false},
	}
	for _, tt := range tests {
		if got := isNgswManifest(mustParseURL(t, tt.raw)); got != tt.want {
			t.Errorf("isNgswManifest(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestParseNgswManifestAssets(t *testing.T) {
	base := mustParseURL(t, "https://svc-a.dev.platform.example.com/ngsw.json")

	// Real-shaped ngsw.json: assetGroups list prefetch urls; hashTable keys cover
	// the full versioned asset set (including chunks absent from assetGroups).
	body := `{
		"configVersion": 1,
		"timestamp": 1700000000000,
		"index": "/index.html",
		"assetGroups": [
			{
				"name": "app",
				"installMode": "prefetch",
				"urls": [
					"/index.html",
					"/main.e2d7eff37dafe1be.js",
					"/polyfills.76a95cf66416d3a9.js",
					"/runtime.b634ae702caa8b86.js"
				],
				"patterns": []
			},
			{
				"name": "assets",
				"installMode": "lazy",
				"urls": [
					"/100.f4ec506ea243a497.js",
					"/161.eb53268fd01f650f.js"
				],
				"patterns": []
			}
		],
		"hashTable": {
			"/index.html": "aaa",
			"/100.f4ec506ea243a497.js": "bbb",
			"/909.90f8ccc126747cd3.js": "ccc",
			"/ngsw-worker.js": "ddd",
			"/styles.abc123.css": "eee",
			"https://evil.example.org/offsite.js": "fff"
		},
		"navigationUrls": []
	}`

	got := sortedURLStrings(parseNgswManifestAssets(base, []byte(body)))
	origin := "https://svc-a.dev.platform.example.com"

	// Lazy chunk present only in hashTable must be recovered.
	if !contains(got, origin+"/909.90f8ccc126747cd3.js") {
		t.Errorf("missing hashTable-only chunk in %v", got)
	}
	// Chunk in both assetGroups and hashTable should appear exactly once.
	n := 0
	for _, u := range got {
		if u == origin+"/100.f4ec506ea243a497.js" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("chunk 100 appeared %d times, want 1 (dedup failed): %v", n, got)
	}
	// Cross-origin asset must be dropped (same-origin scope).
	for _, u := range got {
		if u == "https://evil.example.org/offsite.js" {
			t.Errorf("cross-origin asset leaked into result: %v", got)
		}
	}
	// Non-fetchable assets (css, index.html) must be filtered out.
	for _, u := range got {
		if u == origin+"/styles.abc123.css" || u == origin+"/index.html" {
			t.Errorf("non-fetchable asset leaked into result: %v", u)
		}
	}
	// Prefetch bundles present too.
	if !contains(got, origin+"/main.e2d7eff37dafe1be.js") {
		t.Errorf("missing main bundle in %v", got)
	}
}

func TestParseNgswManifestAssetsGarbage(t *testing.T) {
	base := mustParseURL(t, "https://example.com/ngsw.json")
	if got := parseNgswManifestAssets(base, []byte(`not json at all`)); got != nil {
		t.Errorf("garbage body: got %v, want nil", sortedURLStrings(got))
	}
	if got := parseNgswManifestAssets(base, nil); got != nil {
		t.Errorf("nil body: got %v, want nil", sortedURLStrings(got))
	}
}
