package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

func TestNormalizeToRoot(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path/to/page?q=1", "https://example.com/"},
		{"https://example.com", "https://example.com/"},
		{"http://example.com:8080/foo", "http://example.com:8080/"},
		{"https://example.com/", "https://example.com/"},
		{"https://example.com/path#fragment", "https://example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeToRoot(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeToRoot(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeToRootEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Scheme-less inputs get the default https:// scheme applied. A bare
		// "example.com" parses as a path (no authority), so after rooting the
		// path the host is empty — documents the actual (lossy) behavior and
		// exercises the u.Scheme == "" branch.
		{"no scheme bare host parses as path", "example.com", "https:///"},
		{"no scheme with leading slashes keeps host", "//example.com/path", "https://example.com/"},
		// Already-rooted URLs with a non-default scheme are preserved.
		{"explicit http scheme", "http://example.com/foo?bar=1", "http://example.com/"},
		// Parse failures fall back to returning the input verbatim. A control
		// byte makes url.Parse return an error.
		{"unparseable input returned verbatim", "http://\x7f\x00bad", "http://\x7f\x00bad"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeToRoot(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeToRoot(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestContainsHTMLMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"html tag", `<html lang="en"><body></body></html>`, true},
		{"head tag deep in body", `<!-- comment -->\n<head><title>x</title></head>`, true},
		{"body tag", `<root><body>content</body></root>`, true},
		{"doctype mixed case", `<!DOCTYPE html>`, true},
		{"lowercase doctype", `<!doctype html>`, true},
		{"no html markers (real XML)", `<rss version="2.0"><channel><item/></channel></rss>`, false},
		{"empty body", ``, false},
		{"marker only after the 4096-byte scan window is missed",
			strings.Repeat("x", 5000) + "<html>", false},
		{"marker within the 4096-byte scan window is found",
			strings.Repeat("x", 100) + "<body>", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsHTMLMarker([]byte(tt.body))
			if got != tt.expected {
				t.Errorf("containsHTMLMarker(%q...) = %v, want %v", truncate(tt.body), got, tt.expected)
			}
		})
	}
}

// truncate shortens a string for readable test failure messages.
func truncate(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

func TestClassifyBlankResponse(t *testing.T) {
	// Build a minimal HTTP response with blank body
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	startType := httpmsg.GetStartType(resp)
	if startType != "[blank]" {
		t.Errorf("expected [blank] for empty body, got %q", startType)
	}
}

func TestClassifyJSONResponse(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}")

	startType := httpmsg.GetStartType(resp)
	if startType != "json" {
		t.Errorf("expected json for JSON body, got %q", startType)
	}
}

func TestClassifyHTMLResponse(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><head><title>Test</title></head><body><a href=\"/link\">Link</a></body></html>")

	startType := httpmsg.GetStartType(resp)
	if startType != "<!DOCTYPE" {
		t.Errorf("expected <!DOCTYPE for HTML body, got %q", startType)
	}
}

func TestClassifyXMLResponse(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n<?xml version=\"1.0\"?><root><item/></root>")

	startType := httpmsg.GetStartType(resp)
	if startType != "<?xml" {
		t.Errorf("expected <?xml for XML body, got %q", startType)
	}
}

func TestClassifyAdvancedNoLinks(t *testing.T) {
	body := []byte("<html><head><title>Empty</title></head><body><p>No links here</p></body></html>")
	result := &HeuristicsResult{ContentType: "html"}
	classifyAdvanced(result, body)

	if result.LinkCount != 0 {
		t.Errorf("expected 0 links, got %d", result.LinkCount)
	}
	if result.IsSPA {
		t.Error("expected IsSPA=false")
	}
	if !result.SkipSpidering {
		t.Error("expected SkipSpidering=true for HTML with no links and not SPA")
	}
}

func TestClassifyAdvancedWithLinks(t *testing.T) {
	body := []byte(`<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>`)
	result := &HeuristicsResult{ContentType: "html"}
	classifyAdvanced(result, body)

	if result.LinkCount != 2 {
		t.Errorf("expected 2 links, got %d", result.LinkCount)
	}
	if result.SkipSpidering {
		t.Error("expected SkipSpidering=false for HTML with links")
	}
}

func TestClassifyAdvancedSPA(t *testing.T) {
	body := []byte(`<html><body><div id="app"></div><script src="/bundle.js"></script></body></html>`)
	result := &HeuristicsResult{ContentType: "html"}
	classifyAdvanced(result, body)

	if !result.IsSPA {
		t.Error("expected IsSPA=true for Vue/React-style SPA")
	}
	if result.SkipSpidering {
		t.Error("expected SkipSpidering=false for SPA")
	}
}

func TestClassifyAdvancedNextJS(t *testing.T) {
	body := []byte(`<html><body><script id="__NEXT_DATA__" type="application/json">{}</script></body></html>`)
	result := &HeuristicsResult{ContentType: "html"}
	classifyAdvanced(result, body)

	if !result.IsSPA {
		t.Error("expected IsSPA=true for Next.js app")
	}
}

func TestLooksLikeHTMLTag(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"link tag", `<link rel="stylesheet" href="/style.css">`, true},
		{"LINK tag", `<LINK rel="stylesheet">`, true},
		{"a tag", `<a href="/">Home</a>`, true},
		{"script tag", `<script src="/app.js"></script>`, true},
		{"SCRIPT tag", `<SCRIPT>alert(1)</SCRIPT>`, true},
		{"noscript tag", `<noscript>Enable JS</noscript>`, true},
		{"div tag", `<div class="wrapper">content</div>`, true},
		{"meta tag", `<meta charset="utf-8">`, true},
		{"title tag", `<title>My Page</title>`, true},
		{"form tag", `<form action="/submit">`, true},
		{"img tag", `<img src="/logo.png">`, true},
		{"nav tag", `<nav><ul><li>Menu</li></ul></nav>`, true},
		{"header tag", `<header>Site Header</header>`, true},
		{"section tag", `<section>Content</section>`, true},
		{"with leading whitespace", "  \n\t<script src=\"/app.js\"></script>", true},
		{"actual XML", `<rss version="2.0"><channel></channel></rss>`, false},
		{"SOAP XML", `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org">`, false},
		{"custom XML element", `<myCustomElement>data</myCustomElement>`, false},
		{"empty body", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeHTMLTag([]byte(tt.body))
			if got != tt.expected {
				t.Errorf("looksLikeHTMLTag(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

// TestProbeTargetUnfollowedRedirectNotSkipped guards the fix for an off-host
// root redirect (classic SSO/login) being mistaken for a blank/empty root page.
// With FollowHostRedirects=true a cross-host 302 is not followed, so the bare
// 302 — typically an empty body — surfaces to probeTarget. The body-only
// classification would otherwise call it "[blank]", confirm via robots/index
// (which also 302 to nowhere), and skip spidering. The 3xx guard must retain it.
func TestProbeTargetUnfollowedRedirectNotSkipped(t *testing.T) {
	opts := types.DefaultOptions()
	opts.FollowHostRedirects = true // same-host-only → cross-host 302 is NOT followed
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	svc := &services.Services{Options: opts}
	r, err := vighttp.NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}

	// Root (and every path) issues an empty-bodied 302 to a different host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://login.other-host.invalid/")
		w.WriteHeader(http.StatusFound) // 302, no body
	}))
	defer srv.Close()

	result := probeTarget(context.Background(), r, srv.URL+"/", "basic")

	if result.StatusCode != 302 {
		t.Fatalf("expected the unfollowed 302 to surface, got status %d (content_type=%q)",
			result.StatusCode, result.ContentType)
	}
	if result.SkipSpidering {
		t.Errorf("a redirecting root must not be skipped, got SkipSpidering=true reason=%q", result.Reason)
	}
	if result.ContentType != "redirect" {
		t.Errorf("expected ContentType=redirect, got %q", result.ContentType)
	}
}

func TestFilterTargetsByHeuristics(t *testing.T) {
	results := map[string]*HeuristicsResult{
		"https://api.example.com":   {SkipSpidering: true, Reason: "API endpoint (JSON)"},
		"https://web.example.com":   {SkipSpidering: false},
		"https://blank.example.com": {SkipSpidering: true, Reason: "blank/empty root page"},
	}

	targets := []string{
		"https://api.example.com",
		"https://web.example.com",
		"https://blank.example.com",
		"https://unknown.example.com", // not in results, should pass through
	}

	filtered := filterTargetsByHeuristics(targets, results, func(hr *HeuristicsResult) bool {
		return hr.SkipSpidering
	})

	expected := []string{"https://web.example.com", "https://unknown.example.com"}
	if len(filtered) != len(expected) {
		t.Fatalf("expected %d targets, got %d: %v", len(expected), len(filtered), filtered)
	}
	for i, got := range filtered {
		if got != expected[i] {
			t.Errorf("filtered[%d] = %q, want %q", i, got, expected[i])
		}
	}
}
