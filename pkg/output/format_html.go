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
	"github.com/vigolium/vigolium/pkg/utils/textutil"
	"github.com/vigolium/vigolium/public"
)

// HTMLReportMeta carries metadata for the HTML report generation.
type HTMLReportMeta struct {
	// NoRedact keeps credential headers, cookie values and sensitive query
	// parameters in the request/response evidence of HTML, PDF, SARIF and
	// Markdown reports. Off by default: those artifacts are made to be shared
	// (SAFE-12). --no-redact / output.redact_evidence: false set it. JSONL and
	// the database always keep the raw exchange.
	NoRedact bool
	// RedactHeaders are extra lowercased header names to redact (operator -H
	// names, live-session header names) on top of the built-in table.
	RedactHeaders   map[string]struct{}
	Title           string
	Version         string
	ScanDuration    string
	ScanTarget      string
	GeneratedAt     string
	ReportSharedURL string
	// OnTrim, when set, receives the body-capping summary after the report is
	// written instead of the generator printing its own inline "Note:" line. Lets
	// a caller fold a short trim summary into its own export listing. Only the
	// HTML format trims; nil keeps the default inline note.
	OnTrim func(ReportTrimInfo)
	// MaxBodyBytes caps each request and response embedded in the Markdown
	// report. Zero means DefaultMarkdownMaxBodyBytes; negative disables the cap.
	MaxBodyBytes int
	// FollowUp composes a ready-to-run vigolium command from its tail
	// arguments (e.g. "finding", "--id", "5"), so a report can pin follow-ups
	// to the same --db/--config/project scope as the run that produced it.
	// Returning "" suppresses the follow-up. Nil renders a bare
	// "vigolium <tail...>".
	FollowUp func(tail ...string) string
	// PDFTimeout bounds the headless Chrome PDF render. Zero means
	// VIGOLIUM_PDF_TIMEOUT (a Go duration) when set, else DefaultPDFTimeout.
	PDFTimeout time.Duration
	// FailOn is the severity threshold (the --fail-on value) at or above which
	// the junit format reports a finding as a failure. Empty means
	// DefaultJUnitFailOn.
	FailOn string
}

// ReportTrimInfo summarizes the body-capping the HTML report applied, so a
// caller can surface it in its own summary instead of the inline note.
type ReportTrimInfo struct {
	BodiesTruncated int
	BodiesDropped   int
	BytesOmitted    int64
}

// Trimmed reports whether any body was shortened or dropped.
func (t ReportTrimInfo) Trimmed() bool {
	return t.BodiesTruncated > 0 || t.BodiesDropped > 0
}

// Summary renders a compact one-line description of what was trimmed (no
// surrounding parentheses), e.g. "trimmed 12, omitted 3 bodies · 8.0 MB". Empty
// when nothing was trimmed.
func (t ReportTrimInfo) Summary() string {
	if !t.Trimmed() {
		return ""
	}
	var parts []string
	if t.BodiesTruncated > 0 {
		parts = append(parts, fmt.Sprintf("trimmed %d", t.BodiesTruncated))
	}
	if t.BodiesDropped > 0 {
		parts = append(parts, fmt.Sprintf("omitted %d", t.BodiesDropped))
	}
	s := strings.Join(parts, ", ") + " bodies"
	if t.BytesOmitted > 0 {
		s += " · " + humanizeReportBytes(t.BytesOmitted)
	}
	return s
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
	emitReportTrim(stats, meta.OnTrim)
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
	emitReportTrim(aw.stats, meta.OnTrim)
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
	emitReportTrim(stats, meta.OnTrim)
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

// emitReportTrim routes the body-capping summary to the caller's OnTrim callback
// when one is set, otherwise falls back to the default inline note. Called at the
// end of each HTML generator so both delivery paths live in one place.
func emitReportTrim(stats reportTrimStats, onTrim func(ReportTrimInfo)) {
	if onTrim != nil {
		onTrim(ReportTrimInfo{
			BodiesTruncated: stats.bodiesTruncated,
			BodiesDropped:   stats.bodiesDropped,
			BytesOmitted:    stats.bytesOmitted,
		})
		return
	}
	logReportTrim(stats)
}

// logReportTrim emits a single operator-facing note when bodies were trimmed, so
// a smaller-than-expected report is never a silent surprise.
func logReportTrim(stats reportTrimStats) {
	if stats.bodiesTruncated == 0 && stats.bodiesDropped == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "  Note: HTML report trimmed %d and omitted %d HTTP bodies (%s) to stay within browser limits; full raw data is available in the sqlite, jsonl, and fs export formats\n",
		stats.bodiesTruncated, stats.bodiesDropped, humanizeReportBytes(stats.bytesOmitted))
}

// trimReportItemJSON trims bulky/binary bodies out of an embedded report envelope
// so the payload stays small enough for a browser to parse. http_record envelopes
// have their base64 request/response bodies capped; finding envelopes have their
// inline request/response and additional-evidence text capped against the SAME
// shared budget — otherwise a finding carrying a multi-MB inline response would
// bypass the budget entirely and bloat the report. Anything else (or anything it
// can't parse) passes through unchanged.
func trimReportItemJSON(raw []byte, budget *int64, stats *reportTrimStats) []byte {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return raw
	}
	var typ string
	if err := json.Unmarshal(env["type"], &typ); err != nil {
		return raw
	}
	switch typ {
	case "http_record":
		return trimReportRecordJSON(raw, env, budget, stats)
	case "finding":
		return trimReportFindingJSON(raw, env, budget, stats)
	default:
		return raw
	}
}

// rewriteReportEnvData decodes an envelope's "data" object, hands it to mutate,
// and re-marshals the envelope. mutate reports whether it changed anything; when
// it didn't (a finding whose fields all fit the budget), the original bytes are
// returned without a wasted marshal round-trip. Any decode/encode error falls back
// to the original bytes. Shared by the record and finding trimmers so the envelope
// round-trip lives in one place.
func rewriteReportEnvData(raw []byte, env map[string]json.RawMessage, mutate func(data map[string]json.RawMessage) bool) []byte {
	var data map[string]json.RawMessage
	if err := json.Unmarshal(env["data"], &data); err != nil {
		return raw
	}
	if !mutate(data) {
		return raw
	}
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

// trimReportRecordJSON drops the redundant raw_request/raw_response copies and
// caps/labels the request_body/response_body of an http_record envelope.
func trimReportRecordJSON(raw []byte, env map[string]json.RawMessage, budget *int64, stats *reportTrimStats) []byte {
	return rewriteReportEnvData(raw, env, func(data map[string]json.RawMessage) bool {
		// Drop the redundant full raw request/response copies — the parsed headers
		// plus the (trimmed) body carry everything the report viewer needs, and
		// raw_response duplicates the body a second time.
		delete(data, "raw_request")
		delete(data, "raw_response")
		trimReportBodyField(data, "response_body", "response_content_type", "response_body_trimmed", "response_body_note", budget, stats)
		trimReportBodyField(data, "request_body", "request_content_type", "request_body_trimmed", "request_body_note", budget, stats)
		return true // always rewrites — the raw_* copies are always dropped
	})
}

// trimReportFindingJSON caps a finding envelope's inline request/response and
// additional-evidence text against the shared body budget, so finding evidence
// can no longer blow the report size the way trimmed http_record bodies used to
// leak around. Response first (usually the largest), then request, then evidence.
func trimReportFindingJSON(raw []byte, env map[string]json.RawMessage, budget *int64, stats *reportTrimStats) []byte {
	return rewriteReportEnvData(raw, env, func(data map[string]json.RawMessage) bool {
		// Each trimmer runs (left operand of ||), and reports whether it shortened
		// anything; a finding that all fits the budget rewrites nothing.
		changed := trimReportTextField(data, "response", budget, stats)
		changed = trimReportTextField(data, "request", budget, stats) || changed
		changed = trimReportEvidenceField(data, budget, stats) || changed
		return changed
	})
}

// trimReportString caps one raw-text string against the body budget, appending an
// explicit truncation/omission marker in place of a separate note field. Returns
// the (possibly shortened) text and whether it changed. Shared by a finding's
// single-string fields and its additional-evidence entries.
func trimReportString(s string, budget *int64, stats *reportTrimStats) (string, bool) {
	newBody, trimmed, note := trimReportBody([]byte(s), "", budget, stats)
	if !trimmed {
		return s, false
	}
	return appendTrimNote(string(newBody), note), true
}

// trimReportTextField caps a single string field (a finding's inline raw
// request/response) in place, reporting whether it changed.
func trimReportTextField(data map[string]json.RawMessage, key string, budget *int64, stats *reportTrimStats) bool {
	raw, ok := data[key]
	if !ok {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return false
	}
	trimmed, changed := trimReportString(s, budget, stats)
	if !changed {
		return false
	}
	data[key], _ = json.Marshal(trimmed)
	return true
}

// trimReportEvidenceField caps each additional_evidence entry (a labeled
// request/response blob) against the same budget, reporting whether any changed.
func trimReportEvidenceField(data map[string]json.RawMessage, budget *int64, stats *reportTrimStats) bool {
	raw, ok := data["additional_evidence"]
	if !ok {
		return false
	}
	var entries []string
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return false
	}
	changed := false
	for i, e := range entries {
		if e == "" {
			continue
		}
		if trimmed, c := trimReportString(e, budget, stats); c {
			entries[i] = trimmed
			changed = true
		}
	}
	if changed {
		data["additional_evidence"], _ = json.Marshal(entries)
	}
	return changed
}

// appendTrimNote appends an explicit truncation/omission marker to trimmed text
// so a shortened finding body never reads as if it were complete.
func appendTrimNote(body, note string) string {
	if note == "" {
		return body
	}
	if body == "" {
		return "…[" + note + "]"
	}
	return body + "\n…[" + note + "]"
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
		// Cut on a rune boundary so a multibyte body never ends in half a
		// character; the bytes up to the cut are kept verbatim.
		keep = textutil.CutIndex(body, htmlReportMaxBodyBytes)
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
