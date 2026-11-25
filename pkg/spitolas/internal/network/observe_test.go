package network

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/waf"
)

// Only in-scope document/XHR/fetch responses reach OnResponse.
func TestObserveResponseFilter(t *testing.T) {
	var seen []string
	c := &Capture{
		OnResponse:  func(e *TrafficEntry) { seen = append(seen, e.Request.URL) },
		ScopeFilter: func(host, _ string) bool { return host == "app.test" },
	}
	mk := func(url, rt string) *TrafficEntry {
		return &TrafficEntry{Request: RequestData{URL: url}, ResourceType: rt, Response: &ResponseData{Status: 200}}
	}
	c.observeResponse(mk("https://app.test/", "Document"))
	c.observeResponse(mk("https://app.test/api", "XHR"))
	c.observeResponse(mk("https://app.test/logo.png", "Image"))
	c.observeResponse(mk("https://cdn.other/x", "Fetch"))
	if len(seen) != 2 {
		t.Errorf("observed %v, want the in-scope document and XHR only", seen)
	}
}

// In-scope captured responses that classify as a block or a 2xx challenge reach
// OnBlock with their host; ordinary pages, assets and out-of-scope hosts do not.
// OnBlock works without OnResponse.
func TestObserveResponseBlocks(t *testing.T) {
	type hit struct {
		host   string
		status int
		kind   string
		vendor string
	}
	var hits []hit
	c := &Capture{
		OnBlock: func(host string, status int, b *waf.BlockResult) {
			hits = append(hits, hit{host, status, b.Kind(), b.Vendor()})
		},
		ScopeFilter: func(host, _ string) bool { return host == "app.test" },
	}
	mk := func(url, rt string, status int, hdr map[string]string, body string) *TrafficEntry {
		return &TrafficEntry{Request: RequestData{URL: url}, ResourceType: rt,
			Response: &ResponseData{Status: status, Headers: hdr, Body: []byte(body)}}
	}
	html := map[string]string{"content-type": "text/html"}
	c.observeResponse(mk("https://app.test/", "Document", 200, html, `<script>window._cf_chl_opt={}</script>`))
	c.observeResponse(mk("https://app.test/api", "XHR", 403, nil, "<h1>Forbidden</h1>"))
	c.observeResponse(mk("https://app.test/ok", "Document", 200, html, "<p>hello</p>"))
	c.observeResponse(mk("https://app.test/x.png", "Image", 403, nil, "You have been blocked"))
	c.observeResponse(mk("https://other.test/", "Document", 200, map[string]string{"cf-mitigated": "challenge"}, ""))

	want := []hit{{"app.test", 200, "challenge", "cloudflare"}, {"app.test", 403, "refused", ""}}
	if len(hits) != len(want) {
		t.Fatalf("hits = %+v, want %+v", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Errorf("hit %d = %+v, want %+v", i, hits[i], want[i])
		}
	}
}
