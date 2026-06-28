package database

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestInferSourceType(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"local relative", "./src", SourceTypeLocal},
		{"local absolute", "/home/user/repo", SourceTypeLocal},
		{"gs canonical", "gs://bucket/path", SourceTypeGCS},
		{"gcs alias", "gcs://bucket/path", SourceTypeGCS},
		{"http url", "http://github.com/x/y", SourceTypeGitURL},
		{"https url", "https://github.com/x/y", SourceTypeGitURL},
		{"git ssh", "git@github.com:x/y.git", SourceTypeGitURL},
		{"plain windows-ish path", "C:/repo", SourceTypeLocal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InferSourceType(tt.in); got != tt.want {
				t.Errorf("InferSourceType(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"all empty", []string{"", "", ""}, ""},
		{"no args", nil, ""},
		{"first wins", []string{"a", "b"}, "a"},
		{"skip leading empties", []string{"", "", "third"}, "third"},
		{"second after empty first", []string{"", "second", "third"}, "second"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstNonEmpty(tt.values...); got != tt.want {
				t.Errorf("firstNonEmpty(%v) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestIsValidHTTPVersion(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"HTTP/1.1", true},
		{"HTTP/1.0", true},
		{"HTTP/2", true},
		{"HTTP/2.0", true},
		{"HTTP/10.5", true}, // multi-digit major
		{"HTTP/0.0", false}, // zero major — stdlib placeholder
		{"HTTP/0.9", false}, // zero major
		{"HTTP/", false},    // missing version
		{"1.1", false},      // no HTTP/ prefix
		{"", false},
		{"HTTP/x.y", false}, // non-numeric major
		{"HTTP/.5", false},  // empty major before dot
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isValidHTTPVersion(tt.in); got != tt.want {
				t.Errorf("isValidHTTPVersion(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestExtractResponseHTTPVersion(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"http 1.1", "HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1"},
		{"http 1.0", "HTTP/1.0 404 Not Found\r\n\r\n", "HTTP/1.0"},
		{"http 2", "HTTP/2 200\r\n\r\n", "HTTP/2"},
		{"empty falls back", "", "HTTP/1.1"},
		{"zero major falls back", "HTTP/0.0 200 OK\r\n\r\n", "HTTP/1.1"},
		{"no space falls back", "HTTP/1.1", "HTTP/1.1"},
		{"single line no newline", "HTTP/1.0 301", "HTTP/1.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractResponseHTTPVersion([]byte(tt.raw)); got != tt.want {
				t.Errorf("extractResponseHTTPVersion(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestExtractHTMLTitle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", ""},
		{"no title", "<html><body>hi</body></html>", ""},
		{"simple title", "<html><head><title>Hello World</title></head></html>", "Hello World"},
		{"title trimmed", "<title>   spaced   </title>", "spaced"},
		{"plain text not html", "just some text", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractHTMLTitle([]byte(tt.body)); got != tt.want {
				t.Errorf("extractHTMLTitle(%q) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

func TestExtractHTMLTitle_CapsAt512(t *testing.T) {
	long := make([]byte, 0, 700)
	long = append(long, []byte("<title>")...)
	for i := 0; i < 600; i++ {
		long = append(long, 'a')
	}
	long = append(long, []byte("</title>")...)

	got := extractHTMLTitle(long)
	if len(got) != 512 {
		t.Errorf("expected title capped at 512 chars, got %d", len(got))
	}
}

func TestCountResponseWords(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers []httpmsg.HttpHeader
		want    int64
	}{
		{"empty", "", nil, 0},
		{"three words", "the quick fox", nil, 3},
		{"collapses whitespace", "  the   quick\t\tfox  ", nil, 3},
		{"newlines split words", "line1\nline2\r\nline3", nil, 3},
		{
			name: "headers counted",
			body: "body words here", // 3
			headers: []httpmsg.HttpHeader{
				{Name: "Content-Type", Value: "text/html"}, // "Content-Type"=1, "text/html"=1
			},
			want: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countResponseWords([]byte(tt.body), tt.headers); got != tt.want {
				t.Errorf("countResponseWords(%q, %v) = %d, want %d", tt.body, tt.headers, got, tt.want)
			}
		})
	}
}

func TestResolveHostnameIP_LiteralIP(t *testing.T) {
	// A literal IP must be returned verbatim with no DNS lookup.
	if got := resolveHostnameIP("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("resolveHostnameIP(127.0.0.1) = %q, want 127.0.0.1", got)
	}
	if got := resolveHostnameIP("::1"); got != "::1" {
		t.Errorf("resolveHostnameIP(::1) = %q, want ::1", got)
	}
}

func TestResolveHostnameIP_CachesResult(t *testing.T) {
	// Use a clearly-invalid hostname so the DNS lookup fails and an empty
	// result is cached. Resolution is now asynchronous (it must not block the
	// write path), so the first call returns "" immediately and schedules a
	// background resolve; the cache entry appears once that completes.
	host := "definitely-not-a-real-host.invalid-tld-xyz"
	if first := resolveHostnameIP(host); first != "" {
		t.Errorf("first resolveHostnameIP should return %q (async), got %q", "", first)
	}

	// Wait for the background resolve (a failed lookup) to land in the cache.
	deadline := time.Now().Add(5 * time.Second)
	var cached string
	var found bool
	for time.Now().Before(deadline) {
		dnsCache.RLock()
		cached, found = dnsCache.m[host]
		dnsCache.RUnlock()
		if found {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Fatalf("expected %q to be cached after background lookup", host)
	}

	// Once cached, the value is returned consistently.
	if got := resolveHostnameIP(host); got != cached {
		t.Errorf("resolveHostnameIP not stable: cached %q vs returned %q", cached, got)
	}
}

func TestParameterTypeFromParamType(t *testing.T) {
	tests := []struct {
		in   httpmsg.ParamType
		want string
	}{
		{httpmsg.ParamURL, "url"},
		{httpmsg.ParamBody, "body"},
		{httpmsg.ParamBodyMultipart, "body"},
		{httpmsg.ParamJSON, "json"},
		{httpmsg.ParamXML, "xml"},
		{httpmsg.ParamXMLAttr, "xml"},
		{httpmsg.ParamCookie, "cookie"},
		{httpmsg.ParamPathFolder, "path"},
		{httpmsg.ParamPathFilename, "path"},
		{httpmsg.ParamMultipartAttr, "multipart"},
	}
	for _, tt := range tests {
		if got := ParameterTypeFromParamType(tt.in); got != tt.want {
			t.Errorf("ParameterTypeFromParamType(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveFindingHostname(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		url     string
		matched string
		want    string
	}{
		{"explicit host wins", "api.example.com", "https://other.com/x", "", "api.example.com"},
		{"parse from url", "", "https://example.com/path?q=1", "", "example.com"},
		{"parse from matched when no url", "", "", "https://matched.example.org/p", "matched.example.org"},
		{"url preferred over matched", "", "https://from-url.com/a", "https://from-matched.com/b", "from-url.com"},
		{"all empty", "", "", "", ""},
		{"unparseable falls through to empty", "", "::::not a url", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveFindingHostname(tt.host, tt.url, tt.matched); got != tt.want {
				t.Errorf("resolveFindingHostname(%q,%q,%q) = %q, want %q",
					tt.host, tt.url, tt.matched, got, tt.want)
			}
		})
	}
}

func TestHTTPRecord_FromHttpRequestResponse_GET(t *testing.T) {
	raw := "GET /search?q=book HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer tok123\r\n\r\n"
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}

	var rec HTTPRecord
	if err := rec.FromHttpRequestResponse(rr); err != nil {
		t.Fatalf("FromHttpRequestResponse: %v", err)
	}

	if rec.UUID == "" {
		t.Error("UUID not generated")
	}
	if rec.Method != "GET" {
		t.Errorf("Method = %q, want GET", rec.Method)
	}
	if rec.Hostname != "example.com" {
		t.Errorf("Hostname = %q, want example.com", rec.Hostname)
	}
	// Origin-form raw requests default to https/443 (see ParseRawRequest).
	if rec.Scheme != "https" {
		t.Errorf("Scheme = %q, want https", rec.Scheme)
	}
	if rec.Port != 443 {
		t.Errorf("Port = %d, want 443", rec.Port)
	}
	if rec.Path != "/search?q=book" {
		t.Errorf("Path = %q, want /search?q=book", rec.Path)
	}
	if rec.HTTPVersion != "HTTP/1.1" {
		t.Errorf("HTTPVersion = %q, want HTTP/1.1", rec.HTTPVersion)
	}
	if rec.RequestAuthorization != "Bearer tok123" {
		t.Errorf("RequestAuthorization = %q, want Bearer tok123", rec.RequestAuthorization)
	}
	if len(rec.RawRequest) == 0 {
		t.Error("RawRequest is empty")
	}
	if rec.RequestHash == "" {
		t.Error("RequestHash not computed")
	}
	if rec.HasResponse {
		t.Error("HasResponse should be false with no response")
	}
}

func TestHTTPRecord_FromHttpRequestResponse_CookieFallbackAuth(t *testing.T) {
	// No Authorization header → falls back to Cookie.
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n"
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	var rec HTTPRecord
	if err := rec.FromHttpRequestResponse(rr); err != nil {
		t.Fatalf("FromHttpRequestResponse: %v", err)
	}
	if rec.RequestAuthorization != "session=abc" {
		t.Errorf("RequestAuthorization = %q, want session=abc (cookie fallback)", rec.RequestAuthorization)
	}
}

func TestHTTPRecord_FromHttpRequestResponse_WithResponse(t *testing.T) {
	raw := "GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"
	rr, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}
	body := "<html><head><title>My Page</title></head><body>hello world</body></html>"
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body))
	rr = rr.WithResponse(resp)

	var rec HTTPRecord
	if err := rec.FromHttpRequestResponse(rr); err != nil {
		t.Fatalf("FromHttpRequestResponse: %v", err)
	}

	if !rec.HasResponse {
		t.Fatal("HasResponse should be true")
	}
	if rec.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", rec.StatusCode)
	}
	if rec.ResponseContentType != "text/html" {
		t.Errorf("ResponseContentType = %q, want text/html", rec.ResponseContentType)
	}
	if rec.ResponseTitle != "My Page" {
		t.Errorf("ResponseTitle = %q, want My Page", rec.ResponseTitle)
	}
	if rec.ResponseHTTPVersion != "HTTP/1.1" {
		t.Errorf("ResponseHTTPVersion = %q, want HTTP/1.1", rec.ResponseHTTPVersion)
	}
	if rec.ResponseWords == 0 {
		t.Error("ResponseWords should be > 0")
	}
	if rec.ResponseHash == "" {
		t.Error("ResponseHash not computed")
	}
	if len(rec.RawResponse) == 0 {
		t.Error("RawResponse empty")
	}
}

func TestHTTPRecord_FromHttpRequestResponse_NilGuards(t *testing.T) {
	var rec HTTPRecord
	if err := rec.FromHttpRequestResponse(nil); err == nil {
		t.Error("expected error for nil HttpRequestResponse")
	}
}

func TestFinding_FromResultEvent(t *testing.T) {
	event := &output.ResultEvent{
		ModuleID: "xss-reflected",
		Info: output.Info{
			Name:        "Reflected XSS",
			Description: "Reflected cross-site scripting",
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"xss", "active"},
		},
		Host:               "app.example.com",
		URL:                "https://app.example.com/q?x=1",
		Matched:            "https://app.example.com/q?x=1",
		ExtractedResults:   []string{"<script>"},
		Request:            "GET /q?x=1 HTTP/1.1",
		Response:           "HTTP/1.1 200 OK",
		AdditionalEvidence: []string{"payload echoed"},
		ModuleType:         "active",
		FindingSource:      "scanner",
		ModuleShort:        "xss",
	}

	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}

	if f.ModuleID != "xss-reflected" {
		t.Errorf("ModuleID = %q", f.ModuleID)
	}
	if f.ModuleName != "Reflected XSS" {
		t.Errorf("ModuleName = %q", f.ModuleName)
	}
	if f.Description != "Reflected cross-site scripting" {
		t.Errorf("Description = %q", f.Description)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Confidence != "firm" {
		t.Errorf("Confidence = %q, want firm", f.Confidence)
	}
	if f.URL != "https://app.example.com/q?x=1" {
		t.Errorf("URL = %q", f.URL)
	}
	if f.Hostname != "app.example.com" {
		t.Errorf("Hostname = %q, want app.example.com", f.Hostname)
	}
	if len(f.MatchedAt) != 1 || f.MatchedAt[0] != event.Matched {
		t.Errorf("MatchedAt = %v", f.MatchedAt)
	}
	if len(f.ExtractedResults) != 1 || f.ExtractedResults[0] != "<script>" {
		t.Errorf("ExtractedResults = %v", f.ExtractedResults)
	}
	if f.ModuleType != "active" {
		t.Errorf("ModuleType = %q", f.ModuleType)
	}
	if f.FindingSource != "scanner" {
		t.Errorf("FindingSource = %q", f.FindingSource)
	}
	if f.ModuleShort != "xss" {
		t.Errorf("ModuleShort = %q", f.ModuleShort)
	}
	if f.FindingHash == "" {
		t.Error("FindingHash not set (should be event.ID())")
	}
	if f.FindingHash != event.ID() {
		t.Errorf("FindingHash = %q, want %q", f.FindingHash, event.ID())
	}
	// Native scan findings are trusted by default.
	if f.Status != StatusTriaged {
		t.Errorf("Status = %q, want %q", f.Status, StatusTriaged)
	}
	if f.FoundAt.IsZero() {
		t.Error("FoundAt not set")
	}
}

func TestFinding_FromResultEvent_HostnameFromURL(t *testing.T) {
	// No explicit Host → hostname derived from URL.
	event := &output.ResultEvent{
		ModuleID: "open-redirect",
		Info:     output.Info{Name: "Open Redirect", Severity: severity.Medium},
		URL:      "https://derived.example.com/login?next=//evil",
	}
	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}
	if f.Hostname != "derived.example.com" {
		t.Errorf("Hostname = %q, want derived.example.com", f.Hostname)
	}
}

func TestFinding_FromResultEvent_NilGuard(t *testing.T) {
	var f Finding
	if err := f.FromResultEvent(nil); err == nil {
		t.Error("expected error for nil ResultEvent")
	}
}

// buildRawResponse renders a raw HTTP response with the given content type and body.
func buildRawResponse(contentType, body string) string {
	return "HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\n\r\n" + body
}

func TestFinding_FromResultEvent_StaticResponseWindowed(t *testing.T) {
	marker := "new Function("
	var sb strings.Builder
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&sb, "var x%d = %d; // padding padding padding padding\n", i, i)
	}
	sb.WriteString("eval(" + marker + "'return 1'));\n")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&sb, "var y%d = %d; // padding padding padding padding\n", i, i)
	}
	jsBody := sb.String()
	raw := buildRawResponse("application/javascript", jsBody)

	event := &output.ResultEvent{
		ModuleID:         "unsafe-html-sink",
		Info:             output.Info{Name: "Unsafe HTML Sink", Severity: severity.Medium},
		URL:              "https://app.example.com/static/bundle.js",
		ExtractedResults: []string{"eval(new Function('return 1'))"},
		Response:         raw,
	}
	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}

	if !strings.HasPrefix(f.Response, "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n") {
		t.Errorf("windowed response must keep the full head; got prefix %q", f.Response[:min(80, len(f.Response))])
	}
	if !strings.Contains(f.Response, marker) {
		t.Error("windowed response must include the matched sink")
	}
	if !strings.Contains(f.Response, "bytes truncated") {
		t.Error("large static body must be truncated")
	}
	if len(f.Response) >= len(raw) {
		t.Errorf("windowed response (%d) must be smaller than full (%d)", len(f.Response), len(raw))
	}
	// event.Response must be left intact so the linked http_record keeps the full body.
	if event.Response != raw {
		t.Error("event.Response must not be mutated by conversion")
	}
}

func TestFinding_FromResultEvent_SourceMapWindowedByExtension(t *testing.T) {
	// Source maps are commonly served as application/json — the URL extension must
	// still classify them as static.
	body := strings.Repeat("{\"x\":\"mappings data padding padding padding\"},\n", 400)
	raw := buildRawResponse("application/json", body)
	event := &output.ResultEvent{
		ModuleID: "secret-detect",
		Info:     output.Info{Name: "Secret", Severity: severity.High},
		URL:      "https://app.example.com/static/bundle.js.map",
		Response: raw,
	}
	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}
	if len(f.Response) >= len(raw) || !strings.Contains(f.Response, "bytes truncated") {
		t.Errorf("source map (.map) should be windowed by URL extension; len got=%d full=%d", len(f.Response), len(raw))
	}
}

func TestFinding_FromResultEvent_NonStaticResponseStoredWhole(t *testing.T) {
	body := strings.Repeat("<div>error trace line padding padding padding padding</div>\n", 400)
	raw := buildRawResponse("text/html; charset=utf-8", body)
	event := &output.ResultEvent{
		ModuleID: "error-message-detect",
		Info:     output.Info{Name: "Debug Page in Response", Severity: severity.Low},
		URL:      "https://app.example.com/account",
		Response: raw,
	}
	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}
	if f.Response != raw {
		t.Error("non-static (HTML) response must be stored whole")
	}
}

func TestFinding_FromResultEvent_SmallStaticResponseUnchanged(t *testing.T) {
	raw := buildRawResponse("text/css", "body{color:red}\n")
	event := &output.ResultEvent{
		ModuleID: "x",
		Info:     output.Info{Name: "X", Severity: severity.Info},
		URL:      "https://app.example.com/static/app.css",
		Response: raw,
	}
	var f Finding
	if err := f.FromResultEvent(event); err != nil {
		t.Fatalf("FromResultEvent: %v", err)
	}
	if f.Response != raw {
		t.Errorf("small static body must be stored whole, got %q", f.Response)
	}
}
