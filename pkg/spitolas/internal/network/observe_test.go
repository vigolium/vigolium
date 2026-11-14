package network

import "testing"

// MISS-26: only in-scope document/XHR/fetch responses reach OnResponse.
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
