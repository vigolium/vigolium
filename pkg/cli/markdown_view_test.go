package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func TestCompactRawHTTP(t *testing.T) {
	headers := "HTTP/1.1 200 OK\r\nContent-Type: text/html"
	// Pad past statelessEvidenceWindow on both sides so the match is genuinely
	// windowed (ellipsis on each end) rather than the whole body fitting.
	body := strings.Repeat("a", 600) + "CANARY_HIT" + strings.Repeat("b", 600)
	raw := headers + "\r\n\r\n" + body

	// Needle present → windowed around the match, headers preserved.
	got := compactRawHTTP(raw, []string{"CANARY_HIT"}, 2048)
	if !strings.Contains(got, "CANARY_HIT") {
		t.Fatalf("windowed output dropped the needle: %q", got)
	}
	if !strings.HasPrefix(got, headers) {
		t.Fatalf("headers not preserved: %q", got[:min(40, len(got))])
	}
	if !strings.Contains(got, "…") {
		t.Fatalf("expected ellipsis window markers: %q", got)
	}
	if len(got) >= len(raw) {
		t.Fatalf("windowed output should be shorter than raw (got %d, raw %d)", len(got), len(raw))
	}

	// No needle → capped to bodyCap with a truncation marker.
	capped := compactRawHTTP(raw, nil, 100)
	if !strings.Contains(capped, "more bytes truncated") {
		t.Fatalf("expected cap marker when no needle: %q", capped)
	}
	if !strings.HasPrefix(capped, headers) {
		t.Fatalf("cap path dropped headers")
	}

	// Empty body → just the headers, no panic.
	if out := compactRawHTTP(headers+"\r\n\r\n", nil, 100); out != headers {
		t.Fatalf("empty-body case: got %q want %q", out, headers)
	}
}

func TestRenderFindingMarkdownWindowsResponse(t *testing.T) {
	f := &database.Finding{
		ID:               7,
		Severity:         "high",
		ModuleName:       "Reflected XSS",
		ModuleShort:      "Reflected canary executed",
		ModuleID:         "xss-light",
		Confidence:       "firm",
		ModuleType:       "active",
		FindingSource:    "dynamic-assessment",
		MatchedAt:        []string{"https://t.example/q=CANARY_HIT"},
		ExtractedResults: []string{"CANARY_HIT"},
		Request:          "GET /q=CANARY_HIT HTTP/1.1\r\nHost: t.example",
		Response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			strings.Repeat("x", 400) + "CANARY_HIT" + strings.Repeat("y", 400),
	}

	var sb strings.Builder
	renderFindingMarkdown(f, nil, &sb, true) // compact = true
	out := sb.String()

	for _, want := range []string{"## [HIGH] Reflected XSS", "### Request", "### Response", "```http", "**Module:** `xss-light`"} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q\n---\n%s", want, out)
		}
	}
	// Request is shown whole (payload visible); response is windowed.
	if !strings.Contains(out, "GET /q=CANARY_HIT") {
		t.Fatalf("request payload not rendered:\n%s", out)
	}
	if !strings.Contains(out, "…CANARY_HIT") && !strings.Contains(out, "CANARY_HIT") {
		t.Fatalf("response window missing needle:\n%s", out)
	}
	if strings.Count(out, "y") > 500 {
		t.Fatalf("response not windowed — full body leaked through (compact ignored)")
	}
}

func TestRenderRecordMarkdownRequestOnly(t *testing.T) {
	rec := &database.HTTPRecord{
		Method:      "GET",
		URL:         "https://t.example/a",
		HasResponse: true,
		StatusCode:  200,
		RawRequest:  []byte("GET /a HTTP/1.1\r\nHost: t.example"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody"),
	}
	var sb strings.Builder
	renderRecordMarkdown(rec, &sb, true /*requestOnly*/, false)
	out := sb.String()
	if !strings.Contains(out, "### Request") {
		t.Fatalf("request section missing:\n%s", out)
	}
	if strings.Contains(out, "### Response") {
		t.Fatalf("requestOnly should omit the response section:\n%s", out)
	}
}

func TestHighlightMarkdown(t *testing.T) {
	md := "## [HIGH] Title\n\n**Module:** `mod-id`\n\n```http\nGET / HTTP/1.1\n**not-bold** `not-code`\n```\n"

	// Not a terminal → untouched, so redirected/piped output stays plain Markdown.
	defer terminal.SetIsTerminal(terminal.IsTerminal())
	defer terminal.SetColorEnabled(terminal.IsColorEnabled())
	terminal.SetIsTerminal(false)
	terminal.SetColorEnabled(true)
	if got := highlightMarkdown(md); got != md {
		t.Fatalf("non-TTY highlight should be a no-op:\n%q", got)
	}

	// Interactive terminal → ANSI added for heading / bold / inline code, but the
	// content inside the ```http fence is left verbatim (still greppable).
	terminal.SetIsTerminal(true)
	got := highlightMarkdown(md)
	if !strings.Contains(got, "\x1b[") {
		t.Fatalf("TTY highlight added no ANSI:\n%q", got)
	}
	if !strings.Contains(got, "GET / HTTP/1.1") {
		t.Fatalf("fenced content mangled: %q", got)
	}
	// The bold/code markers inside the fence must survive verbatim — proof the
	// fence body is skipped rather than reformatted.
	if !strings.Contains(got, "**not-bold** `not-code`") {
		t.Fatalf("fence body should not be reformatted:\n%q", got)
	}
}

func TestIsJSONLSource(t *testing.T) {
	dir := t.TempDir()

	jsonl := filepath.Join(dir, "export.jsonl")
	mustWrite(t, jsonl, `{"type":"finding","data":{}}`+"\n")
	if !isJSONLSource(jsonl) {
		t.Fatalf(".jsonl should be detected as JSONL")
	}

	// SQLite magic header, unknown extension → sniffed as not-JSONL.
	sqlitey := filepath.Join(dir, "data.bin")
	mustWrite(t, sqlitey, "SQLite format 3\x00rest-of-header")
	if isJSONLSource(sqlitey) {
		t.Fatalf("SQLite magic header should not be JSONL")
	}

	// Unknown extension but starts with '{' → JSONL.
	noext := filepath.Join(dir, "data.bin2")
	mustWrite(t, noext, "  \n{\"type\":\"http_record\",\"data\":{}}\n")
	if !isJSONLSource(noext) {
		t.Fatalf("brace-leading file should sniff as JSONL")
	}

	// Explicit .sqlite extension is trusted without sniffing.
	sq := filepath.Join(dir, "x.sqlite")
	mustWrite(t, sq, "{not really json}")
	if isJSONLSource(sq) {
		t.Fatalf(".sqlite extension should win over a brace-leading body")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
