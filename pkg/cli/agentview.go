package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// This file builds the compact, token-aware JSON views emitted by the read/query
// commands (finding, traffic, db ls) under --json. The goal is to make Vigolium
// easy to drive from a coding agent: keep the high-signal metadata + headers,
// bound the (often huge) request/response bodies, stub binary/static payloads,
// and surface a windowed evidence snippet for findings — while leaving the full
// bytes one flag away (--full-body / --raw) and the bulk machine format
// untouched (`export --format jsonl`, which keeps the stable {type,data} envelope).

// Default byte caps for bounded body previews. Bodies beyond these are truncated
// with size + sha256 metadata so an agent knows there is more and can re-fetch
// the full bytes on demand.
const (
	agentReqBodyPreviewMax  = 1024
	agentRespBodyPreviewMax = 2048
	agentEvidenceWindow     = 240
	agentGunzipCap          = 1 << 20 // cap decompressed body at 1 MiB
)

// Shared output-shaping flags, registered on finding / traffic / db ls. Only one
// command runs per invocation, so sharing the backing vars is safe (mirrors the
// existing listHost/findingHost pattern).
var (
	jsonFields   []string // --fields: project to these lowercase JSON keys
	jsonCompact  bool     // --compact: metadata only, drop request/response bodies
	jsonFullBody bool     // --full-body: include complete bodies (no truncation/stubbing)
)

// registerAgentJSONFlags adds the shared --fields / --compact / --full-body flags
// to a command's local flag set.
func registerAgentJSONFlags(flags interface {
	StringSliceVar(p *[]string, name string, value []string, usage string)
	BoolVar(p *bool, name string, value bool, usage string)
}) {
	flags.StringSliceVar(&jsonFields, "fields", nil, "Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url)")
	flags.BoolVar(&jsonCompact, "compact", false, "Compact --json: metadata only, omit request/response bodies (best for surveys)")
	flags.BoolVar(&jsonFullBody, "full-body", false, "Include complete request/response bodies in --json (no truncation or binary stubbing)")
}

// agentViewOptions controls how compactRecordView / compactFindingView render.
type agentViewOptions struct {
	fullBody bool     // include complete bodies (no truncation / binary stubbing)
	noBodies bool     // omit request/response bodies entirely (metadata only)
	fields   []string // top-level key projection (lowercase json keys); empty = all
}

// agentViewOptionsFromFlags reads the shared flags into an options struct.
func agentViewOptionsFromFlags() agentViewOptions {
	return agentViewOptions{
		fullBody: jsonFullBody,
		noBodies: jsonCompact,
		fields:   normalizeFieldList(jsonFields),
	}
}

func normalizeFieldList(in []string) []string {
	var out []string
	for _, f := range in {
		if f = strings.TrimSpace(strings.ToLower(f)); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// writeAgentJSON encodes v to stdout as indented JSON with HTML escaping off, so
// body text containing <, >, & stays readable (and cheap in tokens) instead of
// becoming < noise.
func writeAgentJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// splitHeadersBody splits a raw HTTP message into the header block (request/
// status line + headers) and the body, on the first blank line.
func splitHeadersBody(raw []byte) (headers string, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return string(raw[:i]), raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return string(raw[:i]), raw[i+2:]
	}
	return string(raw), nil
}

// maybeGunzip transparently decompresses a gzip-encoded body so previews are
// readable text instead of a binary blob. Falls back to the original bytes on
// any error.
func maybeGunzip(body []byte) []byte {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, agentGunzipCap))
	if err != nil || len(out) == 0 {
		return body
	}
	return out
}

// looksBinaryBytes reports whether b appears to be binary (contains NULs or a
// high ratio of non-printable bytes) and should not be inlined as text.
func looksBinaryBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	sample := b
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	nonPrintable := 0
	for _, c := range sample {
		if c == 0x00 {
			return true
		}
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			nonPrintable++
		}
	}
	return nonPrintable*100/len(sample) > 30
}

// bodyView renders a request/response body as a bounded, token-aware object:
// headers kept verbatim, body decoded + capped, binary/static payloads stubbed.
func bodyView(raw []byte, contentType string, max int, opts agentViewOptions) map[string]any {
	headers, body := splitHeadersBody(raw)
	v := map[string]any{}
	if headers != "" {
		v["raw_headers"] = headers
	}
	if len(body) == 0 {
		return v
	}
	body = maybeGunzip(body)
	sum := sha256.Sum256(body)
	v["body_size"] = len(body)
	v["body_sha256"] = hex.EncodeToString(sum[:])

	if !opts.fullBody && (modkit.IsStaticAssetContentType(contentType) || looksBinaryBytes(body)) {
		v["body_omitted"] = "binary"
		return v
	}
	if opts.fullBody || len(body) <= max {
		v["body"] = string(body)
		return v
	}
	v["body"] = string(body[:max])
	v["body_truncated"] = true
	return v
}

// evidenceSnippet returns a window of text around the first occurrence of any
// needle in body, so an agent sees the proof without the whole page. Returns ""
// when body is empty or no needle (length >= 3) is found.
func evidenceSnippet(body string, needles []string, win int) string {
	if body == "" {
		return ""
	}
	idx := -1
	for _, n := range needles {
		if n = strings.TrimSpace(n); len(n) < 3 {
			continue
		}
		if p := strings.Index(body, n); p >= 0 {
			idx = p
			break
		}
	}
	if idx < 0 {
		return ""
	}
	start := idx - win
	if start < 0 {
		start = 0
	}
	end := idx + win
	if end > len(body) {
		end = len(body)
	}
	snip := body[start:end]
	if start > 0 {
		snip = "…" + snip
	}
	if end < len(body) {
		snip += "…"
	}
	return snip
}

// projectFields restricts m to the given top-level keys (when non-empty),
// silently ignoring unknown keys so an over-broad --fields list still works.
func projectFields(m map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return m
	}
	out := make(map[string]any, len(fields))
	for _, k := range fields {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// hostLabel renders scheme://host[:port], omitting the default port.
func hostLabel(scheme, hostname string, port int) string {
	if port == 0 || (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, hostname)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, hostname, port)
}

// compactRecordView builds the agent-facing JSON object for one HTTP record.
func compactRecordView(rec *database.HTTPRecord, opts agentViewOptions) map[string]any {
	m := map[string]any{
		"uuid":                    rec.UUID,
		"method":                  rec.Method,
		"url":                     rec.URL,
		"host":                    hostLabel(rec.Scheme, rec.Hostname, rec.Port),
		"status_code":             rec.StatusCode,
		"response_content_type":   rec.ResponseContentType,
		"response_content_length": rec.ResponseContentLength,
		"response_time_ms":        rec.ResponseTimeMs,
		"response_words":          rec.ResponseWords,
		"source":                  rec.Source,
	}
	if rec.ScanUUID != "" {
		m["scan_uuid"] = rec.ScanUUID
	}
	if rec.ResponseTitle != "" {
		m["response_title"] = rec.ResponseTitle
	}
	if rec.IP != "" {
		m["ip"] = rec.IP
	}
	if rec.RiskScore != 0 {
		m["risk_score"] = rec.RiskScore
	}
	if rec.IsAuthenticated {
		m["is_authenticated"] = true
	}
	if len(rec.Technology) > 0 {
		m["technology"] = rec.Technology
	}
	if len(rec.Remarks) > 0 {
		m["remarks"] = rec.Remarks
	}

	if !opts.noBodies {
		if len(rec.RawRequest) > 0 {
			m["request"] = bodyView(rec.RawRequest, rec.RequestContentType, agentReqBodyPreviewMax, opts)
		}
		if rec.HasResponse && len(rec.RawResponse) > 0 {
			m["response"] = bodyView(rec.RawResponse, rec.ResponseContentType, agentRespBodyPreviewMax, opts)
		}
	}
	return projectFields(m, opts.fields)
}

// compactFindingView builds the agent-facing JSON object for one finding. When
// records is non-empty (--with-records) the linked HTTP records are embedded
// (bounded by the same body rules); the curated evidence fields
// (matched_at/extracted_results/additional_evidence) and a windowed snippet of
// any inline response keep the proof small by default.
func compactFindingView(f *database.Finding, records []*database.HTTPRecord, opts agentViewOptions) map[string]any {
	m := map[string]any{
		"id":             f.ID,
		"severity":       f.Severity,
		"confidence":     f.Confidence,
		"module_id":      f.ModuleID,
		"module_name":    f.ModuleName,
		"module_type":    f.ModuleType,
		"finding_source": f.FindingSource,
	}
	if f.ModuleShort != "" {
		m["short"] = f.ModuleShort
	}
	if f.Description != "" {
		m["description"] = f.Description
	}
	if f.URL != "" {
		m["url"] = f.URL
	}
	if f.Hostname != "" {
		m["hostname"] = f.Hostname
	}
	if len(f.MatchedAt) > 0 {
		m["matched_at"] = f.MatchedAt
	}
	if len(f.ExtractedResults) > 0 {
		m["extracted_results"] = f.ExtractedResults
	}
	if len(f.AdditionalEvidence) > 0 {
		m["additional_evidence"] = f.AdditionalEvidence
	}
	if len(f.Tags) > 0 {
		m["tags"] = f.Tags
	}
	if f.CWEID != "" {
		m["cwe_id"] = f.CWEID
	}
	if f.CVSSScore != 0 {
		m["cvss_score"] = f.CVSSScore
	}
	if f.Remediation != "" {
		m["remediation"] = f.Remediation
	}
	if f.Status != "" {
		m["status"] = f.Status
	}
	if f.ScanUUID != "" {
		m["scan_uuid"] = f.ScanUUID
	}
	if f.AgenticScanUUID != "" {
		m["agentic_scan_uuid"] = f.AgenticScanUUID
	}
	if f.RepoName != "" {
		m["repo_name"] = f.RepoName
	}
	if f.SourceFile != "" {
		m["source_file"] = f.SourceFile
	}
	m["found_at"] = f.FoundAt.Format(time.RFC3339)
	if len(f.HTTPRecordUUIDs) > 0 {
		m["http_record_uuids"] = f.HTTPRecordUUIDs
	}

	if !opts.noBodies {
		needles := append(append([]string{}, f.ExtractedResults...), f.MatchedAt...)
		if snip := evidenceSnippet(f.Response, needles, agentEvidenceWindow); snip != "" {
			m["response_evidence"] = snip
		} else if f.Response != "" && opts.fullBody {
			m["response"] = f.Response
		}
		if f.Request != "" {
			if opts.fullBody {
				m["request"] = f.Request
			} else {
				m["request"] = clicommon.Truncate(f.Request, agentReqBodyPreviewMax)
			}
		}
	}

	if len(records) > 0 {
		// Nested records carry their own shape; finding-level --fields must not
		// prune their keys, so resolve them with field projection cleared.
		recOpts := opts
		recOpts.fields = nil
		recViews := make([]map[string]any, 0, len(records))
		for _, r := range records {
			recViews = append(recViews, compactRecordView(r, recOpts))
		}
		m["records"] = recViews
	}
	return projectFields(m, opts.fields)
}

// findingViews renders a slice of findings, optionally resolving + embedding the
// linked HTTP records (--with-records).
func findingViews(ctx context.Context, db *database.DB, findings []*database.Finding, opts agentViewOptions, withRecords bool) []map[string]any {
	var repo *database.Repository
	if withRecords {
		repo = database.NewRepository(db)
	}
	views := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		var recs []*database.HTTPRecord
		if withRecords {
			recs = loadFindingRecords(ctx, repo, f)
		}
		views = append(views, compactFindingView(f, recs, opts))
	}
	return views
}

// recordViews renders a slice of HTTP records for agent consumption.
func recordViews(records []*database.HTTPRecord, opts agentViewOptions) []map[string]any {
	views := make([]map[string]any, 0, len(records))
	for _, r := range records {
		views = append(views, compactRecordView(r, opts))
	}
	return views
}
