package cli

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestSeveritiesAtOrAbove(t *testing.T) {
	got := severitiesAtOrAbove("high")
	want := []string{"high", "critical"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("high+: got %v want %v", got, want)
	}
	if severitiesAtOrAbove("bogus") != nil {
		t.Fatalf("unknown threshold should return nil")
	}
	// "medium" should NOT include the less-severe "suspect".
	for _, s := range severitiesAtOrAbove("medium") {
		if s == "suspect" || s == "low" || s == "info" {
			t.Fatalf("medium+ should not include %q", s)
		}
	}
}

func TestEvidenceSnippet(t *testing.T) {
	body := "<html>" + strings.Repeat("x", 500) + "MARKER_VALUE" + strings.Repeat("y", 500) + "</html>"
	snip := evidenceSnippet(body, []string{"MARKER_VALUE"}, 40)
	if !strings.Contains(snip, "MARKER_VALUE") {
		t.Fatalf("snippet missing needle: %q", snip)
	}
	if len(snip) > 120 {
		t.Fatalf("snippet not windowed: len=%d", len(snip))
	}
	if !strings.HasPrefix(snip, "…") || !strings.HasSuffix(snip, "…") {
		t.Fatalf("expected ellipsis markers on both ends: %q", snip)
	}
	if evidenceSnippet(body, []string{"absent"}, 40) != "" {
		t.Fatalf("missing needle should yield empty snippet")
	}
	// Needles shorter than 3 chars are ignored (avoid spurious 1-char matches).
	if evidenceSnippet(body, []string{"x"}, 40) != "" {
		t.Fatalf("short needle should be ignored")
	}
}

func TestLooksBinaryBytes(t *testing.T) {
	if looksBinaryBytes([]byte("plain readable text\nwith newlines")) {
		t.Fatalf("text classified as binary")
	}
	if !looksBinaryBytes([]byte{0x00, 0x01, 0x02, 0x03, 'a', 'b'}) {
		t.Fatalf("NUL-containing bytes should be binary")
	}
}

func TestBodyViewTruncationAndStub(t *testing.T) {
	// Bounded preview with truncation metadata.
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("A", 5000))
	v := bodyView(raw, "text/html", 100, agentViewOptions{})
	if v["body_truncated"] != true {
		t.Fatalf("expected truncation flag, got %v", v)
	}
	if got := v["body"].(string); len(got) != 100 {
		t.Fatalf("body not capped to 100: %d", len(got))
	}
	if v["body_size"].(int) != 5000 {
		t.Fatalf("body_size wrong: %v", v["body_size"])
	}
	if _, ok := v["body_sha256"].(string); !ok {
		t.Fatalf("missing sha256")
	}

	// Static asset content type -> stubbed.
	stub := bodyView([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\nbinarydata"), "image/png", 100, agentViewOptions{})
	if stub["body_omitted"] != "binary" {
		t.Fatalf("expected binary stub, got %v", stub)
	}
	if _, hasBody := stub["body"]; hasBody {
		t.Fatalf("stubbed body should not include bytes")
	}

	// --full-body overrides both truncation and stubbing.
	full := bodyView(raw, "text/html", 100, agentViewOptions{fullBody: true})
	if _, truncated := full["body_truncated"]; truncated {
		t.Fatalf("full-body should not truncate")
	}
	if len(full["body"].(string)) != 5000 {
		t.Fatalf("full-body should return all bytes")
	}
}

func TestBodyViewGunzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("decompressed-secret-payload"))
	_ = zw.Close()
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"), buf.Bytes()...)
	v := bodyView(raw, "application/json", 1000, agentViewOptions{})
	if body, _ := v["body"].(string); !strings.Contains(body, "decompressed-secret-payload") {
		t.Fatalf("gzip body not decoded: %v", v)
	}
}

func TestProjectFields(t *testing.T) {
	m := map[string]any{"id": 1, "severity": "high", "url": "x", "description": "big"}
	out := projectFields(m, []string{"id", "severity", "missing"})
	if len(out) != 2 || out["id"] != 1 || out["severity"] != "high" {
		t.Fatalf("projection wrong: %v", out)
	}
	// Empty field list returns the map unchanged.
	if len(projectFields(m, nil)) != 4 {
		t.Fatalf("nil fields should pass through")
	}
}

func TestCompactRecordViewNoBodies(t *testing.T) {
	rec := &database.HTTPRecord{
		UUID: "u1", Method: "GET", URL: "https://h/x", Scheme: "https", Hostname: "h", Port: 443,
		StatusCode: 200, HasResponse: true,
		RawRequest:  []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody"),
	}
	v := compactRecordView(rec, agentViewOptions{noBodies: true})
	if _, ok := v["request"]; ok {
		t.Fatalf("noBodies should drop request")
	}
	if _, ok := v["response"]; ok {
		t.Fatalf("noBodies should drop response")
	}
	if v["host"] != "https://h" {
		t.Fatalf("default https port should be omitted: %v", v["host"])
	}
}

func TestCompactFindingViewEvidenceAndProjection(t *testing.T) {
	f := &database.Finding{
		ID: 7, Severity: "high", Confidence: "firm", ModuleID: "xss", ModuleType: "active",
		MatchedAt:        []string{"https://h/s?q=PWN"},
		ExtractedResults: []string{"PWN_MARKER"},
		Response:         "<p>echo: PWN_MARKER here</p>" + strings.Repeat("z", 1000),
	}
	v := compactFindingView(f, nil, agentViewOptions{})
	snip, ok := v["response_evidence"].(string)
	if !ok || !strings.Contains(snip, "PWN_MARKER") {
		t.Fatalf("expected evidence snippet, got %v", v["response_evidence"])
	}
	if len(snip) > 600 {
		t.Fatalf("evidence should be windowed, not full body: %d", len(snip))
	}
	// Field projection on a finding.
	proj := compactFindingView(f, nil, agentViewOptions{fields: []string{"id", "severity"}})
	if len(proj) != 2 {
		t.Fatalf("finding projection wrong: %v", proj)
	}
}
