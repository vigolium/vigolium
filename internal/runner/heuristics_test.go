package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
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
