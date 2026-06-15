package output

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func sampleEvent() *ResultEvent {
	return &ResultEvent{
		ModuleID: "xss-reflected",
		Info: Info{
			Name:        "Reflected XSS",
			Description: "User input is reflected without encoding",
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"xss", "active"},
		},
		Type:    "http",
		Host:    "example.com",
		URL:     "https://example.com/search?q=1",
		Matched: "https://example.com/search?q=<script>",
	}
}

func TestResultEventIDDeterministic(t *testing.T) {
	ev := sampleEvent()
	first := ev.ID()
	second := ev.ID()
	assert.Equal(t, first, second, "ID must be stable across calls for the same event")
	// SHA1 hex digest is 40 characters.
	assert.Len(t, first, 40)

	// A separate event with identical ID-relevant fields hashes the same.
	clone := sampleEvent()
	assert.Equal(t, first, clone.ID(), "events with identical hashed fields share an ID")
}

func TestResultEventIDVariesByField(t *testing.T) {
	base := sampleEvent()
	baseID := base.ID()

	cases := []struct {
		name   string
		mutate func(e *ResultEvent)
	}{
		{"module id", func(e *ResultEvent) { e.ModuleID = "sqli" }},
		{"description", func(e *ResultEvent) { e.Info.Description = "different" }},
		{"severity", func(e *ResultEvent) { e.Info.Severity = severity.Low }},
		{"matched", func(e *ResultEvent) { e.Matched = "https://example.com/other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := sampleEvent()
			tc.mutate(ev)
			assert.NotEqual(t, baseID, ev.ID(), "changing %s must change the ID", tc.name)
		})
	}
}

func TestResultEventIDIgnoresUnhashedFields(t *testing.T) {
	base := sampleEvent()
	baseID := base.ID()

	// Fields not folded into the hash must not affect the ID.
	ev := sampleEvent()
	ev.URL = "https://other.example.com/path"
	ev.Host = "other.example.com"
	ev.Request = "GET / HTTP/1.1"
	ev.Info.Name = "Renamed"
	ev.Info.Confidence = severity.Tentative
	assert.Equal(t, baseID, ev.ID(), "URL/Host/Request/Name/Confidence are not part of the ID hash")
}

func TestResultEventIDConcurrent(t *testing.T) {
	// Exercises the sha1Pool under concurrency for a stable result.
	ev := sampleEvent()
	want := ev.ID()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := sampleEvent()
			assert.Equal(t, want, local.ID())
		}()
	}
	wg.Wait()
}

func TestFormatJSONRoundTrips(t *testing.T) {
	w := &StandardWriter{IncludeResponseInOutput: true}
	ev := sampleEvent()
	ev.Response = "HTTP/1.1 200 OK"
	ev.MatcherStatus = true

	data, err := w.formatJSON(ev)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))

	// The JSON tag for ModuleID is "template-id" for Nuclei compatibility.
	assert.Equal(t, "xss-reflected", decoded["template-id"])
	assert.Equal(t, "https://example.com/search?q=1", decoded["url"])
	assert.Equal(t, "https://example.com/search?q=<script>", decoded["matched-at"])
	assert.Equal(t, "http", decoded["type"])
	assert.Equal(t, true, decoded["matcher-status"])
	// Info serializes as a nested "info" object.
	info, ok := decoded["info"].(map[string]any)
	require.True(t, ok, "info object present")
	assert.Equal(t, "Reflected XSS", info["name"])
	assert.Equal(t, "high", info["severity"])
	// Response retained because IncludeResponseInOutput is true.
	assert.Equal(t, "HTTP/1.1 200 OK", decoded["response"])
}

func TestFormatJSONStripsResponseByDefault(t *testing.T) {
	w := &StandardWriter{IncludeResponseInOutput: false}
	ev := sampleEvent()
	ev.Response = "HTTP/1.1 200 OK\r\n\r\nsecret-body"

	data, err := w.formatJSON(ev)
	require.NoError(t, err)

	// The response is omitted from the marshaled JSON when not included...
	assert.NotContains(t, string(data), "secret-body")
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	_, hasResponse := decoded["response"]
	assert.False(t, hasResponse, "response key omitted from output")

	// ...but the caller's event MUST keep its Response. The same *ResultEvent is
	// written to output and then persisted to the DB (e.g. the known-issue scan
	// callback runs before SaveFinding/SaveRecord); mutating it here would wipe
	// the response body from the stored finding and HTTP record.
	assert.Equal(t, "HTTP/1.1 200 OK\r\n\r\nsecret-body", ev.Response,
		"formatJSON must not mutate the caller's event")
}

func TestStandardWriterWriteSetsDefaults(t *testing.T) {
	// DisableStdout avoids polluting test output; no output file is configured.
	w := &StandardWriter{DisableStdout: true}
	ev := &ResultEvent{ModuleID: "mod", Info: Info{Severity: severity.Info}}

	before := time.Now()
	require.NoError(t, w.Write(ev))

	assert.Equal(t, "http", ev.Type, "Type defaults to http")
	assert.True(t, ev.MatcherStatus, "MatcherStatus is forced true for findings")
	assert.False(t, ev.Timestamp.Before(before), "Timestamp is stamped on Write")
}

func TestStandardWriterWriteToFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/out.jsonl"
	fw, err := newFileOutputWriter(path, false)
	require.NoError(t, err)

	w := &StandardWriter{DisableStdout: true, outputFile: fw}
	ev := sampleEvent()
	require.NoError(t, w.Write(ev))
	require.NoError(t, w.Write(sampleEvent()))
	w.Close()

	body := readFile(t, path)
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	require.Len(t, lines, 2, "each Write emits one JSONL line")
	for _, line := range lines {
		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &decoded))
		assert.Equal(t, "xss-reflected", decoded["template-id"])
	}
}

func TestStandardWriterWriteFileOnly(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/file-only.jsonl"
	fw, err := newFileOutputWriter(path, false)
	require.NoError(t, err)

	// DisableStdout is false but WriteFileOnly must never touch stdout.
	w := &StandardWriter{outputFile: fw}
	ev := sampleEvent()
	require.NoError(t, w.WriteFileOnly(ev))
	assert.Equal(t, "http", ev.Type)
	assert.True(t, ev.MatcherStatus)
	w.Close()

	body := readFile(t, path)
	assert.Contains(t, body, "xss-reflected")
}

func TestStandardWriterCloseNilFileIsSafe(t *testing.T) {
	w := &StandardWriter{}
	assert.NotPanics(t, w.Close)
}

func TestStandardWriterShowsFindingsOnStdout(t *testing.T) {
	cases := []struct {
		name          string
		disableStdout bool
		jsonOutput    bool
		want          bool
	}{
		{"console human stream", false, false, true},
		{"silent / deferred suppresses stdout", true, false, false},
		{"raw json on stdout is not human-readable", false, true, false},
		{"both off", true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := &StandardWriter{DisableStdout: c.disableStdout, JSONOutput: c.jsonOutput}
			assert.Equal(t, c.want, w.ShowsFindingsOnStdout())
		})
	}
}

func TestMultiWriterShowsFindingsOnStdout(t *testing.T) {
	// No sub-writer advertises stdout findings.
	mw := NewMultiWriter(&StandardWriter{DisableStdout: true})
	assert.False(t, mw.ShowsFindingsOnStdout())

	// One sub-writer does → the aggregate does.
	mw = NewMultiWriter(&StandardWriter{DisableStdout: true}, &StandardWriter{})
	assert.True(t, mw.ShowsFindingsOnStdout())

	// A writer that doesn't implement the predicate is ignored, not a panic.
	mw = NewMultiWriter(&recordingWriter{})
	assert.False(t, mw.ShowsFindingsOnStdout())
}

func TestFormatPhaseFindingLine(t *testing.T) {
	ev := sampleEvent()
	ev.ModuleType = "passive"
	ev.Request = "GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	line := FormatPhaseFindingLine("dynamic-assessment", ev)
	plain := terminal.StripANSI(line)

	assert.True(t, strings.HasSuffix(line, "\n"), "line is newline-terminated")
	assert.Contains(t, plain, "dynamic-assessment", "carries the phase tag")
	// Mirrors formatScreen's bracketed [type] [module] [severity] layout.
	assert.Contains(t, plain, "[passive]", "module type rendered in brackets")
	assert.Contains(t, plain, "[xss-reflected]", "module id rendered in brackets")
	assert.Contains(t, plain, "high]", "severity rendered in brackets")
	assert.Contains(t, plain, "GET https://example.com/search?q=<script>",
		"HTTP method prefixes the matched-at URL")

	// The [type] bracket is suppressed when it duplicates the phase tag, matching
	// formatScreen.
	kis := sampleEvent()
	kis.ModuleType = "known-issue-scan"
	noType := terminal.StripANSI(FormatPhaseFindingLine("known-issue-scan", kis))
	assert.NotContains(t, noType, "[known-issue-scan]",
		"type bracket suppressed when it duplicates the phase tag")

	// Extracted value is surfaced in brackets and truncated to the cap.
	withVal := sampleEvent()
	withVal.ExtractedResults = []string{strings.Repeat("A", liveFindingValueMax+20)}
	withValue := terminal.StripANSI(FormatPhaseFindingLine("known-issue-scan", withVal))
	assert.Contains(t, withValue, "[")
	assert.NotContains(t, withValue, strings.Repeat("A", liveFindingValueMax+1),
		"value snippet is truncated to the cap")

	// A multi-line extracted snippet (e.g. a JS handler body) renders on one
	// line: embedded newlines become literal \n escapes, never real breaks.
	multiline := sampleEvent()
	multiline.ExtractedResults = []string{"});\n  }\n}\n\nlet intervalId = null;"}
	mlLine := FormatPhaseFindingLine("dynamic-assessment", multiline)
	mlPlain := terminal.StripANSI(mlLine)
	assert.Equal(t, 1, strings.Count(mlLine, "\n"), "only the trailing line terminator is a real newline")
	assert.Contains(t, mlPlain, `});\n  }\n}\n\nlet intervalId`, "embedded newlines escaped to literal \\n")
}

func TestEscapeOneLine(t *testing.T) {
	// Plain values pass through untouched (fast path).
	assert.Equal(t, "no control chars", EscapeOneLine("no control chars"))
	// Newlines, carriage returns, and tabs become literal escapes; a CRLF pair
	// collapses to a single \n.
	assert.Equal(t, `a\nb\tc\nd`, EscapeOneLine("a\nb\tc\r\nd"))
	assert.Equal(t, `\r`, EscapeOneLine("\r"))
	// The result never contains a real control character.
	out := EscapeOneLine("x\ny\tz\r\nw")
	assert.NotContains(t, out, "\n")
	assert.NotContains(t, out, "\r")
	assert.NotContains(t, out, "\t")
}

// recordingWriter is an in-memory Writer that records every event it receives.
type recordingWriter struct {
	written  []*ResultEvent
	fileOnly []*ResultEvent
	closed   int
}

func (r *recordingWriter) Close()                     { r.closed++ }
func (r *recordingWriter) Write(e *ResultEvent) error { r.written = append(r.written, e); return nil }
func (r *recordingWriter) WriteFileOnly(e *ResultEvent) error {
	r.fileOnly = append(r.fileOnly, e)
	return nil
}

func TestMultiWriterDelegatesWrite(t *testing.T) {
	a, b := &recordingWriter{}, &recordingWriter{}
	mw := NewMultiWriter(a, b)

	ev := sampleEvent()
	require.NoError(t, mw.Write(ev))

	require.Len(t, a.written, 1)
	require.Len(t, b.written, 1)
	assert.Same(t, ev, a.written[0], "underlying writer receives the same event pointer")
	assert.Same(t, ev, b.written[0])
}

func TestMultiWriterDelegatesWriteFileOnly(t *testing.T) {
	a, b := &recordingWriter{}, &recordingWriter{}
	mw := NewMultiWriter(a, b)

	ev := sampleEvent()
	require.NoError(t, mw.WriteFileOnly(ev))

	require.Len(t, a.fileOnly, 1)
	require.Len(t, b.fileOnly, 1)
	assert.Empty(t, a.written, "WriteFileOnly does not invoke Write")
}

func TestMultiWriterClosePropagates(t *testing.T) {
	a, b := &recordingWriter{}, &recordingWriter{}
	mw := NewMultiWriter(a, b)
	mw.Close()
	assert.Equal(t, 1, a.closed)
	assert.Equal(t, 1, b.closed)
}

// errWriter fails on Write/WriteFileOnly to verify MultiWriter surfaces errors.
type errWriter struct{ recordingWriter }

func (e *errWriter) Write(*ResultEvent) error         { return assertErr }
func (e *errWriter) WriteFileOnly(*ResultEvent) error { return assertErr }

var assertErr = errTest("boom")

type errTest string

func (e errTest) Error() string { return string(e) }

func TestMultiWriterPropagatesError(t *testing.T) {
	good := &recordingWriter{}
	mw := NewMultiWriter(&errWriter{}, good)

	err := mw.Write(sampleEvent())
	require.Error(t, err)
	assert.Equal(t, "boom", err.Error())
	assert.Empty(t, good.written, "later writers are skipped after an error")
}
