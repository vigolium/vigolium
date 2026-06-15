package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/atomicfile"
	"github.com/vigolium/vigolium/public"
)

// HTMLReportMeta carries metadata for the HTML report generation.
type HTMLReportMeta struct {
	Title           string
	Version         string
	ScanDuration    string
	ScanTarget      string
	GeneratedAt     string
	ReportSharedURL string
}

// HTMLReportData is the template data passed to template.html.
type HTMLReportData struct {
	Title           string
	GeneratedAt     string
	ScanDuration    string
	ScanTarget      string
	VigoliumVersion string
	ReportSharedURL string
	DataExpected    string
	ResultsJSON     template.JS
}

// resolveReportSharedURL returns meta.ReportSharedURL when set, falling back to
// the VIGOLIUM_REPORT_SHARED_URL environment variable. The React template
// substitutes its own default when the value is empty.
func resolveReportSharedURL(meta HTMLReportMeta) string {
	if meta.ReportSharedURL != "" {
		return meta.ReportSharedURL
	}
	return os.Getenv("VIGOLIUM_REPORT_SHARED_URL")
}

// GenerateHTMLReport renders the embedded template.html template
// with the provided items to outputPath. If title is empty it defaults
// to "Vigolium Scan Report".
//
// Each item should be a ready-to-marshal envelope (e.g. struct with
// Type and Data fields). Items are streamed one at a time to keep
// memory usage constant regardless of result set size.
func GenerateHTMLReport(items []any, outputPath string, meta HTMLReportMeta) error {
	title := meta.Title
	if title == "" {
		title = "Vigolium Scan Report"
	}

	// Read embedded template
	tmplBytes, err := public.StaticFS.ReadFile("static-reports/template.html")
	if err != nil {
		return err
	}

	// Split template at the {{.ResultsJSON}} marker so we can stream
	// JSON rows directly instead of holding the entire array in memory.
	const marker = "{{.ResultsJSON}}"
	tmplStr := string(tmplBytes)
	parts := strings.SplitN(tmplStr, marker, 2)

	if len(parts) != 2 {
		// Marker not found — fall back to monolithic marshal
		return generateHTMLReportLegacy(items, outputPath, meta, tmplStr)
	}

	// Create output file with buffered writer
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	w := bufio.NewWriter(f)

	// Replace placeholders in the "before" portion with simple string
	// substitution. We avoid template.Parse because the bundled JS in the
	// template contains sequences (e.g. "{{") that break both html/template
	// and text/template parsers.
	generatedAt := meta.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	before := strings.Replace(parts[0], "{{.Title}}", title, 1)
	before = strings.Replace(before, "{{.GeneratedAt}}", generatedAt, 1)
	before = strings.Replace(before, "{{.ScanDuration}}", meta.ScanDuration, 1)
	before = strings.Replace(before, "{{.ScanTarget}}", meta.ScanTarget, 1)
	before = strings.Replace(before, "{{.VigoliumVersion}}", meta.Version, 1)
	before = strings.Replace(before, "{{.ReportSharedURL}}", resolveReportSharedURL(meta), 1)
	// Signal to the viewer that real data WAS generated. If the data array below
	// is too large for the browser to parse, that <script> throws and leaves
	// window.__VIGOLIUM_REPORT__ undefined — the sentinel lets the viewer show a
	// "failed to load" error instead of silently rendering its demo data.
	before = strings.ReplaceAll(before, "{{.DataExpected}}", "true")
	if _, err := w.WriteString(before); err != nil {
		return err
	}

	// Stream the JSON array, trimming bulky/binary HTTP bodies out of
	// http_record items so the embedded payload stays small enough for a browser
	// to parse. The JSONL export path does NOT trim — it keeps full fidelity.
	var stats reportTrimStats
	if err := writeReportItems(w, items, &stats); err != nil {
		return err
	}

	// Write the "after" portion as-is (no placeholders to substitute)
	if _, err := w.WriteString(parts[1]); err != nil {
		return err
	}

	if err := w.Flush(); err != nil {
		return err
	}
	logReportTrim(stats)
	return nil
}

// ReportItemProducer streams export envelopes to emit, one at a time, in the
// order they should appear in the report. It must return the first error from
// emit (fatal) and should log-and-skip its own data-source errors. Used by
// GenerateHTMLReportStreaming so the report renders without ever materializing
// the whole result set.
type ReportItemProducer func(emit func(any) error) error

// GenerateHTMLReportStreaming renders the embedded template.html to outputPath
// by pulling items from produce one at a time, so the full result set never
// lives in memory. The output is byte-identical to a GenerateHTMLReport call
// over the same items. The report is written to a temp sibling and atomically
// renamed into place on success, so a mid-stream error never leaves a
// half-written report behind.
func GenerateHTMLReportStreaming(produce ReportItemProducer, outputPath string, meta HTMLReportMeta) error {
	title := meta.Title
	if title == "" {
		title = "Vigolium Scan Report"
	}

	tmplBytes, err := public.StaticFS.ReadFile("static-reports/template.html")
	if err != nil {
		return err
	}

	const marker = "{{.ResultsJSON}}"
	tmplStr := string(tmplBytes)
	parts := strings.SplitN(tmplStr, marker, 2)
	if len(parts) != 2 {
		// Marker missing — fall back to the monolithic path, buffering the
		// streamed items (rare: only if the bundled template is malformed).
		var items []any
		if err := produce(func(item any) error { items = append(items, item); return nil }); err != nil {
			return err
		}
		return generateHTMLReportLegacy(items, outputPath, meta, tmplStr)
	}

	generatedAt := meta.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	before := strings.Replace(parts[0], "{{.Title}}", title, 1)
	before = strings.Replace(before, "{{.GeneratedAt}}", generatedAt, 1)
	before = strings.Replace(before, "{{.ScanDuration}}", meta.ScanDuration, 1)
	before = strings.Replace(before, "{{.ScanTarget}}", meta.ScanTarget, 1)
	before = strings.Replace(before, "{{.VigoliumVersion}}", meta.Version, 1)
	before = strings.Replace(before, "{{.ReportSharedURL}}", resolveReportSharedURL(meta), 1)
	before = strings.ReplaceAll(before, "{{.DataExpected}}", "true")

	aw := &reportArrayWriter{budget: int64(htmlReportBodyBudgetBytes)}
	err = atomicfile.Write(outputPath, func(w *bufio.Writer) error {
		aw.w = w
		if _, err := w.WriteString(before); err != nil {
			return err
		}
		if err := produce(func(item any) error { return aw.add(item) }); err != nil {
			return err
		}
		if err := aw.close(); err != nil {
			return err
		}
		_, err := w.WriteString(parts[1])
		return err
	})
	if err != nil {
		return err
	}
	logReportTrim(aw.stats)
	return nil
}

// generateHTMLReportLegacy is the original monolithic approach, used as a
// fallback when the template doesn't contain the expected marker.
func generateHTMLReportLegacy(items []any, outputPath string, meta HTMLReportMeta, tmplStr string) error {
	// Build the array from per-item trimmed JSON (same body capping as the
	// streaming path) rather than a monolithic json.Marshal(items).
	var (
		rowsBuf bytes.Buffer
		stats   reportTrimStats
	)
	if err := writeReportItems(&rowsBuf, items, &stats); err != nil {
		return err
	}
	rowsJSON := rowsBuf.Bytes()

	tmpl, err := template.New("report").Parse(tmplStr)
	if err != nil {
		return err
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	title := meta.Title
	if title == "" {
		title = "Vigolium Scan Report"
	}

	generatedAt := meta.GeneratedAt
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}

	if err := tmpl.Execute(f, HTMLReportData{
		Title:           title,
		GeneratedAt:     generatedAt,
		ScanDuration:    meta.ScanDuration,
		ScanTarget:      meta.ScanTarget,
		VigoliumVersion: meta.Version,
		ReportSharedURL: resolveReportSharedURL(meta),
		DataExpected:    "true",
		ResultsJSON:     template.JS(rowsJSON),
	}); err != nil {
		return err
	}
	logReportTrim(stats)
	return nil
}

// Embedded report body-capping limits. The HTML report inlines its data as a
// single JS array literal in a <script>; an unbounded crawl (thousands of
// records, some carrying multi-MB binary bodies) can push that past the
// browser's parse limit, at which point the script throws and nothing renders.
// These caps keep the embedded payload comfortably parseable. JSONL export is
// unaffected and retains full bodies.
const (
	// htmlReportMaxBodyBytes is the largest single body kept inline; larger
	// textual bodies are truncated to this length.
	htmlReportMaxBodyBytes = 32 * 1024
	// htmlReportBodyBudgetBytes bounds the total kept body bytes across the
	// whole report. Once exhausted, remaining bodies are dropped with a note.
	htmlReportBodyBudgetBytes = 32 * 1024 * 1024
)

// reportTrimStats accumulates what the body-capping dropped or shortened, so it
// can be surfaced to the operator instead of silently truncating.
type reportTrimStats struct {
	bodiesTruncated int   // large textual bodies shortened to the per-body cap
	bodiesDropped   int   // binary or over-budget bodies omitted entirely
	bytesOmitted    int64 // raw body bytes not included in the report
}

// byteWriter is the common surface of *bufio.Writer (streaming) and
// *bytes.Buffer (legacy) used by writeReportItems.
type byteWriter interface {
	io.Writer
	WriteByte(byte) error
}

// reportArrayWriter incrementally writes a JSON array (`[item,item,...]`) of
// trimmed export items to w, one item at a time, so neither the source items
// nor the rendered array ever need to be held whole in memory. Both the
// slice-based writeReportItems and the streaming GenerateHTMLReportStreaming
// drive it, so the body-trimming and array framing live in one place.
type reportArrayWriter struct {
	w       byteWriter
	started bool
	budget  int64
	stats   reportTrimStats
}

func newReportArrayWriter(w byteWriter) *reportArrayWriter {
	return &reportArrayWriter{w: w, budget: int64(htmlReportBodyBudgetBytes)}
}

// add marshals one item, trims its bulky HTTP bodies, and appends it to the
// array (writing the opening '[' on the first call and a ',' separator on
// subsequent ones).
func (a *reportArrayWriter) add(item any) error {
	if !a.started {
		if err := a.w.WriteByte('['); err != nil {
			return err
		}
		a.started = true
	} else if err := a.w.WriteByte(','); err != nil {
		return err
	}
	b, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = a.w.Write(trimReportItemJSON(b, &a.budget, &a.stats))
	return err
}

// close writes the terminating ']', emitting an empty array when no items were
// added.
func (a *reportArrayWriter) close() error {
	if !a.started {
		if err := a.w.WriteByte('['); err != nil {
			return err
		}
		a.started = true
	}
	return a.w.WriteByte(']')
}

// writeReportItems marshals each item, trims bulky HTTP bodies, and writes the
// resulting JSON array (`[item,item,...]`) to w. Shared by the streaming and
// legacy generators so the trimming lives in one place. The per-report body
// budget is owned by the array writer.
func writeReportItems(w byteWriter, items []any, stats *reportTrimStats) error {
	aw := newReportArrayWriter(w)
	for _, item := range items {
		if err := aw.add(item); err != nil {
			return err
		}
	}
	if err := aw.close(); err != nil {
		return err
	}
	*stats = aw.stats
	return nil
}

// logReportTrim emits a single operator-facing note when bodies were trimmed, so
// a smaller-than-expected report is never a silent surprise.
func logReportTrim(stats reportTrimStats) {
	if stats.bodiesTruncated == 0 && stats.bodiesDropped == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "  Note: HTML report trimmed %d and omitted %d HTTP bodies (%s) to stay within browser limits; full bodies are in the JSONL export\n",
		stats.bodiesTruncated, stats.bodiesDropped, humanizeReportBytes(stats.bytesOmitted))
}

// trimReportItemJSON trims bulky/binary HTTP bodies out of an http_record
// envelope so the embedded report payload stays small enough for a browser to
// parse. Non-http_record items (and anything it can't parse) pass through
// unchanged. It drops the redundant raw_request/raw_response copies and
// caps/labels request_body/response_body. budget tracks total kept body bytes.
func trimReportItemJSON(raw []byte, budget *int64, stats *reportTrimStats) []byte {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return raw
	}
	var typ string
	if err := json.Unmarshal(env["type"], &typ); err != nil || typ != "http_record" {
		return raw
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(env["data"], &data); err != nil {
		return raw
	}

	// Drop the redundant full raw request/response copies — the parsed headers
	// plus the (trimmed) body carry everything the report viewer needs, and
	// raw_response duplicates the body a second time.
	delete(data, "raw_request")
	delete(data, "raw_response")

	trimReportBodyField(data, "response_body", "response_content_type", "response_body_trimmed", "response_body_note", budget, stats)
	trimReportBodyField(data, "request_body", "request_content_type", "request_body_trimmed", "request_body_note", budget, stats)

	newData, err := json.Marshal(data)
	if err != nil {
		return raw
	}
	env["data"] = newData
	out, err := json.Marshal(env)
	if err != nil {
		return raw
	}
	return out
}

// trimReportBodyField caps the named base64 body field in data (in place),
// setting the trimmed-flag and note fields when it shortens or drops the body.
// When the body is kept unchanged the original RawMessage is left in place — no
// decode/re-encode round-trip.
func trimReportBodyField(data map[string]json.RawMessage, bodyKey, ctKey, trimmedKey, noteKey string, budget *int64, stats *reportTrimStats) {
	rawBody, ok := data[bodyKey]
	if !ok {
		return
	}
	var body []byte
	if err := json.Unmarshal(rawBody, &body); err != nil || len(body) == 0 {
		return
	}
	var ct string
	if v, ok := data[ctKey]; ok {
		_ = json.Unmarshal(v, &ct)
	}

	newBody, trimmed, note := trimReportBody(body, ct, budget, stats)
	if !trimmed {
		return // unchanged — leave the original base64 in place
	}
	data[bodyKey], _ = json.Marshal(newBody)
	data[trimmedKey], _ = json.Marshal(true)
	data[noteKey], _ = json.Marshal(note)
}

// trimReportBody decides how much of a single body to keep inline. Binary
// bodies are dropped with a label; textual bodies are truncated at the
// per-body cap; once the global budget is exhausted, bodies are dropped. It
// records what it shortened or dropped in stats.
func trimReportBody(body []byte, contentType string, budget *int64, stats *reportTrimStats) (out []byte, trimmed bool, note string) {
	size := humanizeReportBytes(int64(len(body)))
	if isBinaryReportBody(contentType, body) {
		stats.bodiesDropped++
		stats.bytesOmitted += int64(len(body))
		return nil, true, fmt.Sprintf("binary %s body omitted from report (%s) — full body in the JSONL export", reportContentLabel(contentType), size)
	}
	keep := len(body)
	truncated := false
	if keep > htmlReportMaxBodyBytes {
		keep = htmlReportMaxBodyBytes
		truncated = true
	}
	if *budget < int64(keep) {
		stats.bodiesDropped++
		stats.bytesOmitted += int64(len(body))
		return nil, true, fmt.Sprintf("body omitted to keep the report a manageable size (%s) — full body in the JSONL export", size)
	}
	*budget -= int64(keep)
	if truncated {
		stats.bodiesTruncated++
		stats.bytesOmitted += int64(len(body) - keep)
		return body[:keep], true, fmt.Sprintf("body truncated to %s of %s — full body in the JSONL export", humanizeReportBytes(int64(keep)), size)
	}
	return body, false, ""
}

// isBinaryReportBody reports whether a body should be treated as binary (and so
// omitted from the inline report). It trusts an explicit textual/binary
// content-type, and falls back to sniffing the bytes when the type is unknown.
func isBinaryReportBody(contentType string, body []byte) bool {
	ct := strings.ToLower(normalizeContentType(contentType))
	switch {
	case ct == "":
		// unknown — fall through to content sniff
	case strings.HasPrefix(ct, "text/"),
		strings.Contains(ct, "json"),
		strings.Contains(ct, "xml"), // application/xml, image/svg+xml (textual)
		strings.Contains(ct, "javascript"),
		strings.Contains(ct, "ecmascript"),
		strings.Contains(ct, "html"),
		strings.Contains(ct, "x-www-form-urlencoded"),
		strings.Contains(ct, "csv"),
		strings.Contains(ct, "graphql"):
		return false
	case strings.HasPrefix(ct, "image/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"),
		strings.HasPrefix(ct, "font/"),
		strings.Contains(ct, "font"), // application/font-woff, application/x-font-*
		strings.Contains(ct, "pdf"),
		strings.Contains(ct, "zip"),
		strings.Contains(ct, "gzip"),
		strings.Contains(ct, "octet-stream"),
		strings.Contains(ct, "protobuf"),
		strings.Contains(ct, "wasm"),
		strings.Contains(ct, "msword"),
		strings.Contains(ct, "officedocument"),
		strings.Contains(ct, "x-msdownload"):
		return true
	}
	return looksBinaryReportBody(body)
}

// looksBinaryReportBody sniffs up to the first 1 KiB for a NUL byte or a high
// proportion of control bytes — a cheap "is this binary" heuristic.
func looksBinaryReportBody(body []byte) bool {
	n := len(body)
	if n > 1024 {
		n = 1024
	}
	if n == 0 {
		return false
	}
	nonText := 0
	for _, b := range body[:n] {
		if b == 0 {
			return true
		}
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			nonText++
		}
	}
	return nonText*100/n > 30
}

// normalizeContentType trims a Content-Type to its bare type, dropping any
// `; charset=...` parameters and surrounding whitespace.
func normalizeContentType(contentType string) string {
	ct := strings.TrimSpace(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// reportContentLabel returns a short content-type label for trim notes.
func reportContentLabel(contentType string) string {
	if ct := normalizeContentType(contentType); ct != "" {
		return ct
	}
	return "unknown-type"
}

// humanizeReportBytes formats a byte count as B/KB/MB for trim notes.
func humanizeReportBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}
