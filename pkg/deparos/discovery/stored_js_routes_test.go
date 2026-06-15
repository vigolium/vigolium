package discovery

import (
	"net/url"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// TestIsJavaScriptResponse covers the gate that decides which stored responses
// extractRoutesFromStoredJS feeds to the JS route extractor: it must accept JS by
// MIME type AND by URL extension (framework bundles are often served with an odd
// content-type, e.g. Salesforce's application/x-javascript aurafile bundles whose
// path ends in .js before a query string), and reject non-JS.
func TestIsJavaScriptResponse(t *testing.T) {
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return u
	}

	tests := []struct {
		name string
		url  string
		mime string
		want bool
	}{
		{"standard js mime", "https://x.com/app.js", "text/javascript", true},
		{"x-javascript mime", "https://x.com/lightning.out.js", "application/x-javascript", true},
		{"ecmascript mime", "https://x.com/a", "application/ecmascript", true},
		{"aurafile .js with query, odd mime", "https://x.com/aurafile/%7B%22a%22%3A1%7D/h/apppart1-2.js?ltngOut=true", "application/x-javascript", true},
		{"js extension, empty mime", "https://x.com/chunk-ABC.js", "", true},
		{"mjs extension", "https://x.com/m.mjs", "", true},
		{"cjs extension", "https://x.com/m.cjs", "", true},
		{"html is not js", "https://x.com/page", "text/html", false},
		{"json is not js", "https://x.com/api/data", "application/json", false},
		{"css is not js", "https://x.com/app.css", "text/css", false},
		{"nil url, non-js mime", "", "image/png", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u *url.URL
			if tt.url != "" {
				u = mustURL(tt.url)
			}
			if got := isJavaScriptResponse(u, tt.mime); got != tt.want {
				t.Errorf("isJavaScriptResponse(%q, %q) = %v, want %v", tt.url, tt.mime, got, tt.want)
			}
		})
	}
}

// TestExtractRoutesFromStoredJS is the regression guard for the discovery step
// that mines JS earlier phases (spidering) already captured: a Salesforce Aura
// bundle embeds the captcha iframe route as a string, and discovery — which
// otherwise only parses JS it fetches itself — must extract it from the stored
// body. linkfinder extraction of this exact string is covered in linkfinder's
// rootpath_test; this verifies the storage-walk wiring end to end: a stored JS
// node's body flows through to the engine's observed paths AND, with its query
// preserved, to the extracted requests that become scan tasks.
func TestExtractRoutesFromStoredJS(t *testing.T) {
	const host = "https://login-uat.example.com"

	// Storage that keeps response bodies (as the real discovery storage does).
	scfg := storage.DefaultConfig()
	scfg.TargetURL = host
	scfg.SaveResponseBody = true
	sm, err := storage.NewSiteMap(scfg)
	if err != nil {
		t.Fatalf("NewSiteMap: %v", err)
	}
	t.Cleanup(func() { _ = sm.Close() })

	engine, err := NewEngine(testConfig(host), sm)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { engine.Stop() })

	// Store an Aura app bundle exactly as the spider would, with the captcha route
	// embedded the way it appears in the real myapp bundle.
	jsURL, _ := url.Parse(host + "/aurafile/x/h/apppart1-2.js")
	jsBody := []byte(`(function(){var defs={"HTMLAttributes":{"value":{"src":"/apex/APP_Login_NewCaptcha?source=selfRegCaptcha","id":"reqRegCaptcha"}}};return defs;})();`)
	result := storage.NewResultBuilder().
		WithURL(jsURL).
		WithRequest("GET", nil, nil).
		WithResponse(200, map[string]string{"Content-Type": "application/x-javascript"}, jsBody, int64(len(jsBody)), "application/x-javascript", "", "", 0, 0).
		WithMetadata("spidering", 0, time.Now()).
		Build()
	if err := sm.Store(result); err != nil {
		t.Fatalf("store js node: %v", err)
	}

	// Run the step under test.
	engine.extractRoutesFromStoredJS()

	// The path (query stripped) must land in observed paths for crawling.
	if !engine.GetObservedPaths().Contains([]byte("/apex/APP_Login_NewCaptcha")) {
		t.Errorf("observed paths missing /apex/APP_Login_NewCaptcha (extracted from stored Aura JS)")
	}

	// And the full path WITH its query must be queued as an extracted request, so
	// the captcha endpoint is actually fetched with its reflected param.
	foundReq := false
	for _, r := range engine.GetExtractedRequests() {
		if r.URL == "/apex/APP_Login_NewCaptcha?source=selfRegCaptcha" {
			foundReq = true
			break
		}
	}
	if !foundReq {
		t.Errorf("extracted requests missing /apex/APP_Login_NewCaptcha?source=selfRegCaptcha (query not preserved from stored JS)")
	}
}
