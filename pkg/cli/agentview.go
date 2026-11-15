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
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
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
	jsonFields      []string // --fields: project to these lowercase JSON keys
	jsonCompact     bool     // --compact: metadata only, drop request/response bodies
	jsonFullBody    bool     // --full-body: include complete bodies (no truncation/stubbing)
	jsonRecordField []string // --record-fields: projection for NESTED --with-records rows
	jsonRecordLimit int      // --record-limit: cap embedded records per finding
)

// defaultRecordLimit bounds how many linked HTTP records one finding embeds
// under --with-records. Unbounded, a single finding can carry hundreds (422 was
// observed in the wild), which is a triage bundle nobody asked for.
const defaultRecordLimit = 20

// registerAgentJSONFlags adds the shared --fields / --compact / --full-body flags
// to a command's local flag set.
func registerAgentJSONFlags(flags *pflag.FlagSet) {
	flags.StringSliceVar(&jsonFields, "fields", nil, "Restrict --json output to these top-level keys (comma-separated, e.g. id,severity,url). An unknown name is an error, not a silent drop")
	flags.BoolVar(&jsonCompact, "compact", false, "With --json, emit metadata only: omit request/response bodies and each finding's description, remediation and additional_evidence (name one in --fields to keep it). --markdown already compacts response bodies by default; use --full-body to render them whole")
	flags.BoolVar(&jsonFullBody, "full-body", false, "Render complete request/response bodies (no truncation/stubbing) with --json, and whole (uncompacted) bodies with --markdown")
	registerOutputBudgetFlag(flags)
}

// registerRowShapingFlags adds --fields, --compact and --max-output-bytes to a
// list command whose rows are structs (rowShaping). --full-body is left off:
// those rows carry no stored bodies for it to expand.
func registerRowShapingFlags(flags *pflag.FlagSet) {
	flags.StringSliceVar(&jsonFields, "fields", nil, "Restrict --json rows to these keys (comma-separated). Aliases such as status/length/title are accepted and emitted under the name you pass. An unknown name is an error, not a silent drop")
	flags.BoolVar(&jsonCompact, "compact", false, "With --json, drop each row's bulky keys (sample lists, excerpts, headers) and keep its metadata")
	registerOutputBudgetFlag(flags)
}

// registerAgentRecordFlags adds the nested-record controls. Only `finding` embeds
// records, so only it registers these.
func registerAgentRecordFlags(flags *pflag.FlagSet) {
	flags.StringSliceVar(&jsonRecordField, "record-fields", nil, "With --with-records: restrict each embedded HTTP record to these keys (independent of --fields)")
	flags.IntVar(&jsonRecordLimit, "record-limit", defaultRecordLimit, "With --with-records: max HTTP records embedded per finding (0 = no cap)")
}

// agentViewOptions controls how compactRecordView / compactFindingView render.
type agentViewOptions struct {
	fullBody bool     // include complete bodies (no truncation / binary stubbing)
	noBodies bool     // omit request/response bodies entirely (metadata only)
	fields   []string // top-level key projection (lowercase json keys); empty = all
	// recordFields projects the NESTED records of --with-records. It is separate
	// from fields because the two describe different entities: a finding-level
	// allowlist applied to a record row would prune it to nothing.
	recordFields []string
	recordLimit  int // max embedded records per finding; 0 = no cap

	// hostFacts serves each record's DNS/TLS observations. nil falls back to the
	// process caches, which is all a caller without a database handle can offer -
	// and all this view had before observations were stored, with the cache's
	// 8192-entry eviction quietly deciding which records got facts. Every method
	// is nil-safe, so consumers never branch on it.
	hostFacts *database.StoredHostFacts

	// notFound answers matches_not_found from the origin's stored not-found
	// baseline; nil when the view did not ask for it.
	notFound *notFoundMatcher

	// redact masks credentials in the raw views (json_redact.go): header
	// values, cookie values and sensitive query parameters. Bodies are kept.
	redact bool
}

// withHostFacts returns a copy of opts that serves host facts from a run's
// stored observations. A database without them yields a reader that answers from
// the process caches, so this is always safe to call.
func (o agentViewOptions) withHostFacts(ctx context.Context, db *database.DB, projectUUID, scanUUID string) agentViewOptions {
	if db == nil {
		return o
	}
	o.hostFacts = database.NewStoredHostFacts(ctx, database.NewRepository(db), projectUUID, scanUUID)
	return o
}

// withNotFound returns a copy of opts that answers matches_not_found, when the
// projection asks for it; otherwise opts unchanged, so no baseline is read.
func (o agentViewOptions) withNotFound(ctx context.Context, db *database.DB, projectUUID string) agentViewOptions {
	if wantsField(o.fields, "matches_not_found") {
		o.notFound = newNotFoundMatcher(ctx, db, projectUUID)
	}
	return o
}

// agentViewOptionsFromFlags reads the shared flags into an options struct.
func agentViewOptionsFromFlags() agentViewOptions {
	return agentViewOptions{
		fullBody:     jsonFullBody,
		noBodies:     jsonCompact,
		fields:       normalizeFieldList(jsonFields),
		recordFields: normalizeFieldList(jsonRecordField),
		recordLimit:  jsonRecordLimit,
		redact:       jsonRedactOn,
	}
}

// validateAgentViewFlags checks the output-shaping flags before any query runs:
// the projection names against the view that will render them, and the output
// budget against the mode that would enforce it. Every command registering
// registerAgentJSONFlags calls it, so a flag added there is validated once.
func validateAgentViewFlags(opts agentViewOptions, supported []string) error {
	if err := validateFieldSelection(opts.fields, supported); err != nil {
		return err
	}
	// --record-fields always describes an HTTP record, whichever command carries it.
	if err := validateFieldSelection(opts.recordFields, trafficViewFields); err != nil {
		return err
	}
	return validateOutputBudgetFlag(globalJSON)
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

// writeAgentJSON writes a command's RESULT document: to stdout, or to the file
// -o/--output named, with a small receipt taking its place on stdout.
//
// It takes the envelope and nothing else. It used to take `any`, and every
// command that hand-built a map or passed its own struct got a document with no
// schema_version, command, ok or kind — the RAW shapes the machine contract
// exists to remove. With this signature a command cannot ship one without the
// compiler noticing; emitRead/emitObject/emitMutation/envelopeFromStruct build
// the envelope.
//
// Only result documents belong here. The error envelope (writeErrorFrame) and
// the -o receipt (writeReceiptFrame) have their own writers: filing an error
// object under `"artifact": "json_result"` would be a lie, and a receipt that
// could itself be redirected has nowhere left to report.
func writeAgentJSON(env *agentEnvelope) error {
	if err := applyGenericShaping(env); err != nil {
		return err
	}
	if jsonCompact {
		compactEnvelope(env)
	}
	if readTSV {
		return writeEnvelopeTSV(env)
	}
	// Attached here rather than at each call site: every -j read that can be
	// sourced from --glob-db funnels through this function, and a per-command
	// hook is one a new command forgets — which is how a merged read with a
	// skipped file reported a clean short answer in the first place.
	attachGlobSources(env)
	stampSendsTraffic(env)
	return writeResultDocument(env)
}

// writeResultDocument is the tail of writeAgentJSON: budget, then stdout or
// the -o file.
func writeResultDocument(v any) error {
	// Before any destination is chosen: a budgeted document is the same
	// document whether it goes to stdout or to a file, which is the invariant
	// encodeAgentJSON exists to hold.
	//
	// It hands back the bytes it measured, so a budgeted document is encoded once
	// here rather than once to decide where to cut and again to emit.
	var fullItems any
	if env, ok := v.(*agentEnvelope); ok {
		fullItems = env.Items
	}
	doc, err := applyOutputBudget(v, maxOutputBytes)
	if err != nil {
		return err
	}
	if doc == nil {
		if doc, err = encodeAgentJSON(v); err != nil {
			return err
		}
	}
	if jsonResultDeferred && !jsonStreamMode {
		// Execute publishes it once the exit code is known (json_outcome.go),
		// to stdout or to the -o file.
		holdJSONResult(&heldJSONResult{
			v: v, doc: doc, items: fullItems, budgeted: maxOutputBytes > 0,
			dest: jsonOutputDestination(),
		})
		return nil
	}
	if dest := jsonOutputDestination(); dest != "" {
		// Deliberately NOT latching here: nothing has reached stdout yet. The latch
		// belongs after publication, and writeJSONResultToFile sets it when it writes
		// the receipt. Latching first meant a failed atomicfile.WriteBytes returned an
		// error that the root handler then refused to frame, so `-j -o <unwritable>`
		// exited non-zero with completely empty stdout.
		return writeJSONResultToFile(dest, doc, v)
	}
	return writeAgentJSONDoc(doc)
}

// writeErrorFrame writes the error envelope straight to stdout. Never through
// writeAgentJSON: -o/--output redirects the RESULT document, and an error is not
// one. Routing it there would write the failure into the file the caller
// expected results in, and leave stdout carrying a receipt for it.
func writeErrorFrame(env agentErrorEnvelope) error {
	return writeStdoutFrame(env)
}

// writeReceiptFrame writes a receipt — the stdout stand-in for a result that
// went somewhere else (the -o file, or body bytes written to a path) — straight
// to stdout. A receipt that could itself be redirected has nowhere left to
// report.
func writeReceiptFrame(receipt any) error {
	return writeStdoutFrame(receipt)
}

// writeStdoutFrame encodes v with the shared encoder and writes it to stdout.
// Unexported to the frame writers above, so the only ways onto stdout are a
// result envelope, an error, or a receipt.
func writeStdoutFrame(v any) error {
	doc, err := encodeAgentJSON(v)
	if err != nil {
		return err
	}
	if jsonResultDeferred && !jsonStreamMode {
		holdJSONResult(&heldJSONResult{v: v, doc: doc})
		return nil
	}
	return writeAgentJSONDoc(doc)
}

// writeAgentJSONDoc writes an already-encoded document and latches. Separate
// from writeStdoutFrame so a caller that has the exact bytes in hand —
// applyOutputBudget measured them — does not encode the same value twice.
func writeAgentJSONDoc(doc []byte) error {
	_, err := os.Stdout.Write(doc)
	jsonResultEmitted = true
	return err
}

// encodeAgentJSON renders v for every -j destination, which is what makes a file
// written with -o byte-identical to the document the same command prints without
// it. A second copy of this configuration is a silent divergence waiting for the
// next encoder option.
//
// The document is compact — one line plus the trailing newline — unless the
// global --pretty (or $VIGOLIUM_JSON_PRETTY=1) asked for indentation. A program
// pays for every indent byte and reads none of them.
//
// In stream mode each document must occupy exactly one line, which is what makes
// a repeated read (--watch) readable with a line-oriented consumer; indented
// output would emit a multi-line object per tick and the "stream" would only be
// splittable by a full JSON parser, so --pretty does not apply there. HTML
// escaping stays off so body text containing <, >, & stays readable — and cheap
// in tokens.
func encodeAgentJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if globalPretty && !jsonStreamMode {
		enc.SetIndent("", "  ")
	}
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// jsonStreamMode switches -j output from one document to NDJSON: one compact
// document per line, even under --pretty. Set only by a repeated read
// (--watch), where a single document is not the shape of the answer.
var jsonStreamMode bool

// jsonStreamFramed records that this invocation's stdout is an NDJSON stream, so
// the one-document latch below does not apply to it.
//
// Set when --watch enters stream mode and never cleared, including after
// jsonStreamMode is reset on return: the frame the stream was written in is a
// property of the whole invocation, and the error line is appended once the
// loop has already exited. A stream that stops because the read broke must say
// so on the stream — the alternative is a consumer tailing lines that simply
// stop arriving, with the cause only in the exit code of a process it may not
// be waiting on.
var jsonStreamFramed bool

// jsonResultEmitted records that a command has already written its JSON result
// document to stdout.
//
// It exists to keep the --json contract at exactly one document per invocation.
// The error path in Execute appends a structured error object on any non-nil
// error, which is right when the command produced nothing — but a --fail-on-match
// hit, a --fail-on severity gate, and any failure after a partial write all
// arrive with a complete result already on stdout, and a second top-level object
// there turns a parseable document into a stream that json.Unmarshal rejects.
// The exit code still carries the outcome.
var jsonResultEmitted bool

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

// decodeResult describes what came out of gunzipBounded. The distinction it
// carries is the whole point: `Bytes` is what the caller may show, `FullSize`
// and `FullSHA256` describe the body that actually exists. Reporting the capped
// length as the body's size made a partial body indistinguishable from a
// complete one, and hashing only the retained prefix produced a `body_sha256`
// that could not be used as the dedupe key it is documented to be.
type decodeResult struct {
	Bytes      []byte // decoded bytes, capped at agentGunzipCap
	FullSize   int    // size of the COMPLETE decoded body (see SizeIsFloor)
	FullSHA256 string // sha256 over the complete decoded body ("" when unmeasured)
	Capped     bool   // the decoder stopped at agentGunzipCap; Bytes is a prefix
	// SizeIsFloor marks FullSize as a lower bound rather than the exact size:
	// the measuring pass gave up at agentMeasureCap. Reported as
	// body_size_at_least so a floor is never mistaken for a measurement.
	SizeIsFloor bool
}

// agentMeasureCap bounds the measuring pass. DEFLATE reaches ~1032:1, so
// draining "the rest of the stream" is attacker-controlled work: a 508 KiB
// stored body expands to 512 MiB and turned a sub-millisecond decode into
// ~325ms, per response, on bodies that come from the scanned target. 64 MiB
// keeps the worst case in the tens of milliseconds and is far above any real
// response, and exceeding it downgrades the answer to a floor rather than
// spending unbounded CPU to refine it.
const agentMeasureCap = 64 << 20

// gunzipBounded decompresses a gzip body while holding at most agentGunzipCap
// bytes in memory.
//
// measure asks for the true size and digest of the WHOLE stream, which requires
// decompressing past the cap; the remainder is drained through a hash and
// discarded, so the answer costs CPU but not memory. Without that drain the
// decoder cannot tell a stream that ENDED at the cap from one that was CUT
// there — io.LimitReader returns io.EOF for both — which is why an oversized
// body used to come back looking complete.
//
// Only bodyView needs the measurement. Text-only callers pass false and pay
// nothing for fields they would discard.
func gunzipBounded(body []byte, measure bool) decodeResult {
	stored := decodeResult{Bytes: body, FullSize: len(body)}
	if !looksGzip(body) {
		return stored
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return stored
	}
	defer func() { _ = zr.Close() }()

	out, err := io.ReadAll(io.LimitReader(zr, agentGunzipCap))
	if err != nil || len(out) == 0 {
		// Undecodable or empty: fall back to the stored bytes exactly as before.
		return stored
	}

	res := decodeResult{Bytes: out, FullSize: len(out)}
	if len(out) < agentGunzipCap {
		// The stream ended inside the cap, so what we hold IS the whole body.
		return res
	}

	// Exactly at the cap: the stream may or may not continue. One byte settles
	// it, and that is all a non-measuring caller needs to know.
	var probe [1]byte
	n, _ := io.ReadFull(zr, probe[:])
	if n == 0 {
		return res
	}
	res.Capped = true
	if !measure {
		// FullSize would be a floor we are not reporting; leave it at the prefix
		// length and let Capped carry the meaning.
		return res
	}

	h := sha256.New()
	h.Write(out)
	h.Write(probe[:n])
	total := int64(len(out) + n)
	drained, derr := io.Copy(h, io.LimitReader(zr, agentMeasureCap))
	total += drained
	res.FullSize = int(total)
	switch {
	case derr != nil:
		// A mid-stream failure means the total describes only what was readable.
		res.SizeIsFloor = true
	case drained == agentMeasureCap:
		// Hit the measuring bound: more may remain, so the size is a floor and a
		// digest over a prefix would be worse than none.
		res.SizeIsFloor = true
	default:
		res.FullSHA256 = hex.EncodeToString(h.Sum(nil))
	}
	return res
}

// maybeGunzip transparently decompresses a gzip-encoded body so previews are
// readable text instead of a binary blob. Falls back to the original bytes on
// any error. Text-only callers (evidence snippets, Markdown rendering) use this;
// bodyView calls gunzipBounded directly because it must report completeness.
func maybeGunzip(body []byte) []byte {
	return gunzipBounded(body, false).Bytes
}

// decodedResponseText returns a raw HTTP response with its body gzip-decoded so
// text searches (evidence snippets) match even when the body is stored
// compressed on the wire — the scanner sends its own Accept-Encoding, so Go's
// transport leaves gzip bodies undecoded and findings persist them as-is.
// Headers are preserved so header-located evidence still matches. The common
// (uncompressed) case returns the original string without allocating a copy.
func decodedResponseText(raw string) string {
	if raw == "" {
		return raw
	}
	// Locate the header/body boundary on the string directly to avoid copying
	// the whole response just to peek at the body's first two bytes.
	sep := 4
	i := strings.Index(raw, "\r\n\r\n")
	if i < 0 {
		sep = 2
		i = strings.Index(raw, "\n\n")
	}
	if i < 0 {
		return raw // no body
	}
	body := raw[i+sep:]
	if !looksGzip([]byte(body)) {
		return raw // not gzip — search the stored bytes as-is
	}
	return raw[:i+sep] + string(maybeGunzip([]byte(body)))
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
		v["raw_headers"] = redactRaw(opts.redact, headers)
	}
	if len(body) == 0 {
		return v
	}

	dec := gunzipBounded(body, true)
	body = dec.Bytes
	// The size of the body that EXISTS, not of the slice we kept — those differ
	// whenever the gzip decoder capped, and reporting the latter is what let a
	// 2.5 MB response present as a complete 1 MiB one. When the measuring pass
	// hit its own bound the number is a floor, and is named as one.
	if dec.SizeIsFloor {
		v["body_size_at_least"] = dec.FullSize
	} else {
		v["body_size"] = dec.FullSize
	}

	// Only fingerprint the body when the caller can't see the full bytes
	// (stubbed, truncated, or decoder-capped) — that's when an agent needs the
	// hash to dedupe or decide to re-fetch. Hashing a fully-inlined body would
	// just burn cycles over bytes the caller already has.
	addHash := func() {
		switch {
		case dec.FullSHA256 != "":
			// Covers the whole decompressed stream, including the part past the
			// cap that was drained rather than retained.
			v["body_sha256"] = dec.FullSHA256
		case !dec.Capped:
			sum := sha256.Sum256(body)
			v["body_sha256"] = hex.EncodeToString(sum[:])
		}
		// Capped with no measured digest: a hash of the prefix would be a
		// fingerprint of something the caller never asked about. Emit nothing.
	}

	// A decoder cap is not a display choice: --full-body cannot lift it, so it is
	// reported separately from body_truncated and names the escape hatch.
	if dec.Capped {
		v["decoder_capped"] = true
		v["decoder_limit"] = agentGunzipCap
		// Names the one-call escape hatch rather than the tree exporter: the
		// caller wants these bytes, not this record's every part.
		v["decoder_hint"] = "body exceeds the JSON decoder limit; get the whole body with: vigolium traffic body --uuid <uuid> -o <file>"
	}

	if !opts.fullBody && (modkit.IsStaticAssetContentType(contentType) || looksBinaryBytes(body)) {
		v["body_omitted"] = "binary"
		addHash()
		return v
	}

	// One exit for the body. "Truncated" is decoder-capped OR sliced for display;
	// --full-body suppresses only the second, which is why the cap still reports.
	shown, truncated := body, dec.Capped
	if !opts.fullBody && len(body) > max {
		shown, truncated = body[:max], true
	}
	v["body"] = string(shown)
	if truncated {
		v["body_truncated"] = true
		addHash()
	}
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

// Public JSON field names each view can emit. These are the SELECTABLE names —
// the vocabulary --fields is checked against — and they are deliberately not the
// SQLite column names (`host` here is `hostname` in storage). A key that is only
// emitted when its value is non-empty still belongs here: "supported but absent"
// and "not a field" are different answers, and conflating them is what sent
// callers hunting for `response_body_sha256`, `title` and `sent_at`.
var (
	// Host-fact keys are appended from database.HostFactsFieldNames rather than
	// re-spelled here: a fact added to that struct reaches --fields with its
	// emitter, instead of being a selectable name nothing ever produces.
	trafficViewFields = append([]string{
		"uuid", "method", "url", "host", "status_code",
		"response_content_type", "response_content_length", "response_time_ms",
		"response_words", "source", "scan_uuid", "sent_at", "response_title", "ip",
		"risk_score", "surface_score", "is_authenticated", "technology", "remarks",
		"body_compaction", "request", "response",
		// Emitted only when --fields names them: uuid_short is the resolvable
		// 8-character prefix (record_ref.go), response_headers the response's
		// header block without its body.
		"uuid_short", "response_headers", "matches_not_found",
	}, database.HostFactsFieldNames...)
	findingViewFields = []string{
		"id", "finding_hash", "severity", "confidence", "module_id", "module_name", "module_type",
		"finding_source", "record_kind", "evidence_grade", "short", "description",
		"url", "hostname", "matched_at", "extracted_results", "additional_evidence",
		"tags", "cwe_id", "cvss_score", "remediation", "status", "status_note", "status_actor", "scan_uuid",
		"agentic_scan_uuid", "repo_name", "source_file", "found_at",
		"http_record_uuids", "origin_record_uuid", "insertion_point", "payload", "verification", "verified_at",
		"response_evidence", "request", "response",
		"records", "records_total", "records_truncated", "records_error",
	}
)

// validateFieldSelection rejects a --fields name the view cannot emit, naming the
// supported set. It runs BEFORE the query, so a typo costs nothing.
//
// This used to be a silent drop, which made an unsupported field, a misspelled
// field and a genuinely null value one indistinguishable outcome: the caller got
// exit 0 and a row with the key simply missing, and concluded the data was not
// there. Failing loudly is the only way that distinction reaches a machine.
//
// A name is supported when the view carries it, or when it is another spelling
// of a concept the view carries (field_vocab.go): `--fields status,length` works
// on `traffic` as it does on `fuzz`.
func validateFieldSelection(fields, supported []string) error {
	if len(fields) == 0 {
		return nil
	}
	has := func(k string) bool { return slices.Contains(supported, k) }
	var unknown, hints []string
	for _, f := range fields {
		if _, ok := resolveFieldName(f, has); !ok {
			unknown = append(unknown, f)
			if near := closestName(f, supported); near != "" {
				hints = append(hints, f+" → "+near)
			}
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	msg := fmt.Sprintf("unknown --fields name(s): %s", strings.Join(unknown, ", "))
	if len(hints) > 0 {
		msg += "\n\ndid you mean: " + strings.Join(hints, ", ")
	}
	msg += "\n\nsupported fields: " + strings.Join(supported, ", ")
	if aliases := fieldAliasesFor(supported); len(aliases) > 0 {
		msg += "\n\nalso accepted (emitted under the name you pass): " + strings.Join(aliases, ", ")
	}
	return usageErrorf("%s", msg)
}

// projectFields restricts m to the given top-level keys (when non-empty).
// Unknown names never reach here — validateFieldSelection rejects them up front.
// always is a set of keys the caller explicitly asked for through another flag
// and which a projection must therefore not remove (see projectionAlways).
func projectFields(m map[string]any, fields []string, always ...string) map[string]any {
	if len(fields) == 0 {
		return m
	}
	out := make(map[string]any, len(fields)+len(always))
	has := func(k string) bool { _, ok := m[k]; return ok }
	for _, k := range fields {
		// Emitted under the name asked for, whichever spelling the view uses.
		if key, ok := resolveFieldName(k, has); ok {
			out[k] = m[key]
		}
	}
	// A field allowlist expresses "narrow the columns", not "undo the other flag
	// I passed". --with-records asks for the linked evidence by name, so a
	// --fields list that happens not to mention `records` must not delete it:
	// that combination silently returned a finding with no evidence at all.
	for _, k := range always {
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
		"url":                     redactURL(opts.redact, rec.URL),
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
	// When the exchange was sent, in UTC: the time --from/--to and
	// --sort sent_at act on.
	if !rec.SentAt.IsZero() {
		m["sent_at"] = rec.SentAt.UTC().Format(time.RFC3339)
	}
	if rec.ResponseTitle != "" {
		m["response_title"] = rec.ResponseTitle
	}
	if rec.IP != "" {
		m["ip"] = rec.IP
	}
	// Host facts (full DNS answer, TLS certificate) through the one owner, so
	// this view and the JSONL export cannot disagree about which keys exist or
	// when they appear. Served from the run's stored observations when the caller
	// supplied them, and otherwise from this process's caches — which is what
	// made the keys appear for a sweep's last hosts and not its first, since
	// those caches evict at 8192 entries. FactsMap memoizes the rendered map, so
	// the JSON round trip it costs is paid per endpoint rather than per record.
	maps.Copy(m, opts.hostFacts.FactsMap(rec.Hostname, rec.Port))
	if rec.RiskScore != 0 {
		m["risk_score"] = rec.RiskScore
	}
	if rec.SurfaceScore != 0 {
		m["surface_score"] = rec.SurfaceScore
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
	// Present only on a record `db compact` shortened, so a reader of the
	// request/response below knows it holds a head, and what the whole was.
	if rec.BodyCompaction != nil {
		m["body_compaction"] = rec.BodyCompaction
	}

	// Opt-in keys: computed only when asked for, so a default row pays nothing.
	if wantsField(opts.fields, "uuid_short") {
		m["uuid_short"] = uuidShort(rec.UUID)
	}
	if wantsField(opts.fields, "matches_not_found") {
		if v, known := opts.notFound.Matches(rec); known {
			m["matches_not_found"] = v
		}
	}
	if wantsField(opts.fields, "response_headers") && rec.HasResponse && len(rec.RawResponse) > 0 {
		headers, _ := splitHeadersBody(rec.RawResponse)
		m["response_headers"] = redactRaw(opts.redact, headers)
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
	// --compact is identity, location, severity, confidence and the one-line
	// short: the general prose (about a kilobyte per finding, the same for
	// every finding of a module) stays out unless --fields names it.
	prose := func(key string) bool { return !opts.noBodies || wantsField(opts.fields, key) }
	m := map[string]any{
		"severity":       f.Severity,
		"confidence":     f.Confidence,
		"module_id":      f.ModuleID,
		"module_name":    f.ModuleName,
		"module_type":    f.ModuleType,
		"finding_source": f.FindingSource,
		"record_kind":    f.RecordKind,
		"evidence_grade": f.EvidenceGrade,
	}
	// id is the store's row id, absent on a finding that was never persisted
	// (a direct scan with no store, see findingViewFromEvent) — a 0 would read
	// as a real id and resolve to nothing, or to another row.
	if f.ID != 0 {
		m["id"] = f.ID
	}
	// finding_hash is the finding's stable identity: the dedup key, what SARIF
	// fingerprints are built from, and the only identity an unpersisted finding
	// (no id) has.
	if f.FindingHash != "" {
		m["finding_hash"] = f.FindingHash
	}
	if f.ModuleShort != "" {
		m["short"] = f.ModuleShort
	}
	if f.Description != "" && prose("description") {
		m["description"] = f.Description
	}
	if f.URL != "" {
		m["url"] = redactURL(opts.redact, f.URL)
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
	if len(f.AdditionalEvidence) > 0 && prose("additional_evidence") {
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
	if f.Remediation != "" && prose("remediation") {
		m["remediation"] = f.Remediation
	}
	if f.Status != "" {
		m["status"] = f.Status
	}
	// The verdict's provenance (`finding mark --note/--by`): why and by whom.
	if f.StatusNote != "" {
		m["status_note"] = f.StatusNote
	}
	if f.StatusActor != "" {
		m["status_actor"] = f.StatusActor
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
	// Replay context and the latest `finding verify` result.
	if f.OriginRecordUUID != "" {
		m["origin_record_uuid"] = f.OriginRecordUUID
	}
	if f.InsertionPoint != nil {
		m["insertion_point"] = f.InsertionPoint
	}
	if f.Payload != "" {
		m["payload"] = f.Payload
	}
	if f.Verification != nil {
		m["verification"] = f.Verification
	}
	if f.VerifiedAt != nil {
		m["verified_at"] = f.VerifiedAt.Format(time.RFC3339)
	}

	if !opts.noBodies {
		needles := append(append([]string{}, f.ExtractedResults...), f.MatchedAt...)
		// Decode the body before searching so evidence in gzip-compressed
		// responses is still found (the needle was matched against decoded text).
		if snip := evidenceSnippet(decodedResponseText(f.Response), needles, agentEvidenceWindow); snip != "" {
			m["response_evidence"] = snip
		} else if f.Response != "" && opts.fullBody {
			m["response"] = redactRaw(opts.redact, f.Response)
		}
		if f.Request != "" {
			req := redactRaw(opts.redact, f.Request)
			if opts.fullBody {
				m["request"] = req
			} else {
				m["request"] = clicommon.Truncate(req, agentReqBodyPreviewMax)
			}
		}
	}

	// Keys the caller asked for through a flag other than --fields. A projection
	// narrows columns; it must not silently undo a different flag.
	pinned := []string{}
	if len(records) > 0 {
		// Nested records carry their own shape; the finding-level --fields list
		// describes a finding and would prune a record row to nothing, so nested
		// rows use their own --record-fields projection instead.
		recOpts := opts
		recOpts.fields = opts.recordFields
		// A record projection that names no body key means the bodies are about to
		// be discarded — so don't decode, gunzip and stringify them first.
		if len(opts.recordFields) > 0 &&
			!slices.Contains(opts.recordFields, "request") &&
			!slices.Contains(opts.recordFields, "response") {
			recOpts.noBodies = true
		}
		recViews := make([]map[string]any, 0, len(records))
		for _, r := range records {
			recViews = append(recViews, compactRecordView(r, recOpts))
		}
		m["records"] = recViews
		pinned = append(pinned, "records")
		// State the relation size whenever it differs from what was embedded, so a
		// bounded bundle is never mistaken for the finding's complete evidence.
		// These are pinned alongside `records`: a projection that dropped them
		// would turn a partial bundle back into an apparently complete one.
		if len(records) < len(f.HTTPRecordUUIDs) {
			m["records_total"] = len(f.HTTPRecordUUIDs)
			m["records_truncated"] = true
			pinned = append(pinned, "records_total", "records_truncated")
		}
	}
	return projectFields(m, opts.fields, pinned...)
}

// findingViewFromEvent renders an in-memory scan result in the same shape
// `finding -j` gives the stored row: the event goes through the converter the
// finding writer uses (database.Finding.FromResultEvent), then through
// compactFindingView. It is the one way a result that never reached a store is
// rendered for a machine, so the scan document's items cannot drift from the
// read path — the nuclei-shaped output.ResultEvent keys (template-id,
// matched-at, info{}) are an import and legacy format, never a -j shape.
//
// Such a finding has no id; finding_hash is its identity. scanUUID and
// projectUUID are the run's, as the writer would stamp them.
func findingViewFromEvent(ev *output.ResultEvent, scanUUID, projectUUID string, opts agentViewOptions) map[string]any {
	var f database.Finding
	if err := f.FromResultEvent(ev); err != nil {
		return nil
	}
	f.ScanUUID = scanUUID
	f.ProjectUUID = projectUUID
	return compactFindingView(&f, nil, opts)
}

// findingViews renders a slice of findings, optionally resolving + embedding the
// linked HTTP records (--with-records). Records for the whole page are fetched in
// one query (not per finding) to avoid an N+1 round-trip pattern.
func findingViews(ctx context.Context, db *database.DB, findings []*database.Finding, opts agentViewOptions, withRecords bool) []map[string]any {
	var byUUID map[string]*database.HTTPRecord
	var loadErr error
	if withRecords {
		byUUID, loadErr = batchLoadFindingRecords(ctx, db, findings, opts.recordLimit)
	}
	views := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		var recs []*database.HTTPRecord
		if withRecords {
			recs = recordsForFinding(byUUID, f)
		}
		v := compactFindingView(f, recs, opts)
		// "the link query failed" and "this finding has no linked records" used to
		// be the same empty answer. An agent triaging on that concludes there is no
		// evidence, when in fact the evidence was never read.
		if withRecords && loadErr != nil && len(f.HTTPRecordUUIDs) > 0 {
			v["records_error"] = fmt.Sprintf("linked records could not be loaded: %v", loadErr)
			v["records_total"] = len(f.HTTPRecordUUIDs)
		}
		views = append(views, v)
	}
	return views
}

// batchLoadFindingRecords fetches every HTTP record referenced across the given
// findings in a single query, keyed by UUID, so embedding records into N
// findings costs one round-trip instead of N.
//
// The error is returned rather than swallowed: a failed lookup and a finding
// with no links both produce an empty map, and the caller is the only place that
// can tell the reader which one happened.
// perFinding caps how many of each finding's links are fetched. The cap belongs
// on the QUERY, not on the rendered output: one finding in the wild links 422
// records, and at ~55 KB of raw request/response each that is ~23 MB read and
// held to render 20 rows.
func batchLoadFindingRecords(ctx context.Context, db *database.DB, findings []*database.Finding, perFinding int) (map[string]*database.HTTPRecord, error) {
	seen := make(map[string]struct{})
	var uuids []string
	for _, f := range findings {
		links := f.HTTPRecordUUIDs
		if perFinding > 0 && len(links) > perFinding {
			links = links[:perFinding]
		}
		for _, u := range links {
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				uuids = append(uuids, u)
			}
		}
	}
	if len(uuids) == 0 {
		return nil, nil
	}
	// When the --glob-db merge left record rows or bodies out, the evidence has to
	// come from the source files instead. See loadGlobFindingRecords for why the
	// merge cannot simply keep them.
	if globMergeOmittedRecords() {
		return loadGlobFindingRecords(ctx, findings, uuids), nil
	}
	records, err := database.NewRepository(db).GetRecordsByUUIDs(ctx, uuids)
	if err != nil {
		return nil, err
	}
	byUUID := make(map[string]*database.HTTPRecord, len(records))
	for _, r := range records {
		byUUID[r.UUID] = r
	}
	return byUUID, nil
}

// projectTypedViews applies a --fields projection to rows that are typed structs
// rather than maps (the scan views). It round-trips through JSON so the
// projection sees exactly the keys the envelope would have emitted, and it does
// so ONLY when a projection was asked for — an unprojected page keeps its
// original encoding path and pays nothing.
//
// An unknown name is rejected against the row's own key set, which is derived
// from the data rather than a hand-kept list: a second copy of a 39-field struct
// is a copy that drifts.
func projectTypedViews(views any, fields []string) (any, error) {
	if len(fields) == 0 {
		return views, nil
	}
	raw, err := jsonMarshalNoEscape(views)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		if err := validateFieldSelection(fields, slices.Sorted(maps.Keys(rows[0]))); err != nil {
			return nil, err
		}
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, projectFields(r, fields))
	}
	return out, nil
}

// loadFindingRecordsOrWarn is the human-render counterpart to the -j path's
// explicit records_error: the render cannot carry a structured field, so a
// failed lookup is announced on stderr rather than shown as absent evidence.
func loadFindingRecordsOrWarn(ctx context.Context, db *database.DB, findings []*database.Finding) map[string]*database.HTTPRecord {
	byUUID, err := batchLoadFindingRecords(ctx, db, findings, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s linked HTTP records could not be loaded: %v\n", terminal.WarnPrefix(), err)
	}
	return byUUID
}

// recordViews renders a slice of HTTP records for agent consumption.
func recordViews(records []*database.HTTPRecord, opts agentViewOptions) []map[string]any {
	views := make([]map[string]any, 0, len(records))
	for _, r := range records {
		views = append(views, compactRecordView(r, opts))
	}
	return views
}
