package autopilot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// Rate-limit thresholds for report_finding. A well-calibrated autopilot run
// produces ~10 findings; past these thresholds the model is almost always
// looping or double-reporting. The soft threshold nudges, the hard cap
// returns an error result so the model can't keep spamming the DB.
const (
	reportFindingSoftWarn = 50
	reportFindingHardCap  = 200
)

// FindingSink is the subset of the database repository the report_finding
// tool needs. Keeping this narrow lets us swap in a test double and keeps
// the tool's import surface tight.
type FindingSink interface {
	SaveFindingDirect(ctx context.Context, finding *database.Finding) error
}

// ReportFindingContext pins the scope under which findings are recorded.
// One instance per autopilot run. The counter increments for every
// successful save so the tool can surface a running tally to the model.
type ReportFindingContext struct {
	Repo            FindingSink
	ProjectUUID     string
	ScanUUID        string // legacy scan id (may be empty for pure-agent runs)
	AgenticScanUUID string // vigolium AgenticScan row id
	Target          string // default URL/host for findings missing one
	Count           atomic.Int64
}

// NewReportFindingTool builds the report_finding tool. ctx is shared —
// findings accumulate into ctx.Count.
func NewReportFindingTool(ctx *ReportFindingContext) tool.Tool {
	return &reportFindingTool{ctx: ctx}
}

type reportFindingTool struct{ ctx *ReportFindingContext }

func (*reportFindingTool) Name() string     { return "report_finding" }
func (*reportFindingTool) Label() string    { return "Record finding" }
func (*reportFindingTool) Category() string { return tool.CategoryVigolium }
func (*reportFindingTool) IsReadOnly() bool { return false }
func (*reportFindingTool) Description() string {
	return "Persist a security finding to the vigolium database. Call this for each concrete vulnerability you discover — duplicates are handled automatically via content hashing. Use specific titles and evidence; don't record speculative issues."
}

func (*reportFindingTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title": map[string]any{
				"type":        "string",
				"description": "Short, specific finding title (e.g., 'JWT verifier accepts alg=none').",
			},
			"severity": map[string]any{
				"type":        "string",
				"enum":        []string{"critical", "high", "medium", "low", "info"},
				"description": "Calibrated severity based on exploit preconditions.",
			},
			"description": map[string]any{
				"type":        "string",
				"description": "1–3 sentences: what the bug is and why it matters in this context.",
			},
			"remediation": map[string]any{
				"type":        "string",
				"description": "1–2 sentences on how to fix it.",
			},
			"cwe_id": map[string]any{
				"type":        "string",
				"description": "CWE classifier, e.g. 'CWE-327'. Omit if unsure.",
			},
			"source_file": map[string]any{
				"type":        "string",
				"description": "Relative file path for whitebox findings (e.g., pkg/auth/jwt.go:47).",
			},
			"url": map[string]any{
				"type":        "string",
				"description": "Target URL for dynamic findings.",
			},
			"confidence": map[string]any{
				"type":        "string",
				"enum":        []string{"certain", "firm", "tentative"},
				"description": "How certain you are. Default 'firm'.",
				"default":     "firm",
			},
			"status": map[string]any{
				"type":        "string",
				"enum":        []string{"triaged", "draft", "false_positive", "accepted_risk", "fixed"},
				"description": "Finding lifecycle state. Default 'triaged'.",
				"default":     "triaged",
			},
			"tags": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Classification tags (e.g., [auth, jwt]).",
			},
			"request": map[string]any{
				"type":        "string",
				"description": "Optional raw HTTP request that triggered the finding.",
			},
			"response": map[string]any{
				"type":        "string",
				"description": "Optional raw HTTP response demonstrating the issue.",
			},
			"record_uuids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "UUIDs of the http_records that prove this finding (from query_records / inspect_record / replay_request's replay_record_uuid / web_fetch's record_uuid). Link the exchange(s) that demonstrate the bug so the finding is reproducible after the session ends. Prefer this over pasting large raw request/response text.",
			},
			"dedup_key": map[string]any{
				"type":        "string",
				"description": "Optional explicit dedup identifier. When set, overrides the default content hash (title + severity + location + description fingerprint). Use this to force dedup of the same bug across phrasings, or to avoid accidental collapse of two different bugs that share a title.",
			},
		},
		"required": []string{"title", "severity", "description"},
	}
}

func (r *reportFindingTool) Execute(ctx context.Context, args map[string]any, onUpdate tool.UpdateFn) (tool.Result, error) {
	res := r.ctx.PersistFromArgs(ctx, args)
	return tool.Result{
		Content: res.Message,
		IsError: res.IsError,
		Details: res.Details,
	}, nil
}

// PersistFromArgs is the shared core of the report_finding tool and the
// claude-code JSON-block parser. It validates args, applies the rate-limit
// cap, persists the finding, and increments the run counter. The returned
// PersistResult is shaped so the report_finding tool can convert it into a
// tool.Result and the JSON-block path can log a one-liner.
//
// args matches the report_finding tool schema (title/severity/description
// required, plus optional confidence, status, url, source_file, etc.).
func (c *ReportFindingContext) PersistFromArgs(ctx context.Context, args map[string]any) PersistResult {
	if c == nil || c.Repo == nil {
		return PersistResult{
			Message: "report_finding unavailable: no database sink configured for this run",
			IsError: true,
		}
	}

	if current := c.Count.Load(); current >= reportFindingHardCap {
		return PersistResult{
			Message: fmt.Sprintf(
				"report_finding rate-limited: %d findings already recorded for this run (cap=%d). "+
					"This almost always means the loop is double-reporting. "+
					"Call halt_scan with a summary of what you've found.",
				current, reportFindingHardCap),
			IsError: true,
		}
	}

	title, _ := args["title"].(string)
	severity, _ := args["severity"].(string)
	description, _ := args["description"].(string)
	if strings.TrimSpace(title) == "" || strings.TrimSpace(severity) == "" || strings.TrimSpace(description) == "" {
		return PersistResult{
			Message: "report_finding: title, severity, and description are all required",
			IsError: true,
		}
	}

	confidence, _ := args["confidence"].(string)
	if confidence == "" {
		confidence = "firm"
	}
	status, _ := args["status"].(string)
	if status == "" {
		status = "triaged"
	}
	cwe, _ := args["cwe_id"].(string)
	sourceFile, _ := args["source_file"].(string)
	url, _ := args["url"].(string)
	if url == "" {
		url = c.Target
	}
	hostname := extractHostname(url)
	remediation, _ := args["remediation"].(string)
	request, _ := args["request"].(string)
	response, _ := args["response"].(string)
	dedupKey, _ := args["dedup_key"].(string)

	var tags []string
	if raw, ok := args["tags"].([]any); ok {
		for _, t := range raw {
			if s, ok := t.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	// Evidence linkage: the http_records that prove this finding. The model
	// only ever learns valid UUIDs from project-scoped tools (query_records,
	// inspect_record, replay_request, web_fetch), so these are in-project by
	// construction — no DB round-trip to re-verify here (the narrow FindingSink
	// deliberately has no record-read capability). Deduped and bounded so a
	// looping model can't attach an unbounded list.
	recordUUIDs := parseRecordUUIDs(args["record_uuids"])

	var findingHash string
	if trimmed := strings.TrimSpace(dedupKey); trimmed != "" {
		findingHash = hashDedupKey(trimmed)
	} else {
		findingHash = hashFinding(title, severity, sourceFile, url, description)
	}

	finding := &database.Finding{
		ProjectUUID:     c.ProjectUUID,
		HTTPRecordUUIDs: recordUUIDs, // evidence records the model linked (may be empty)
		ScanUUID:        c.ScanUUID,
		AgenticScanUUID: c.AgenticScanUUID,
		URL:             url,
		Hostname:        hostname,
		ModuleID:        "olium-autopilot",
		ModuleName:      "olium autopilot",
		ModuleType:      "ai-agent",
		FindingSource:   "autopilot",
		ModuleShort:     truncate(title, 80),
		Description:     composeDescription(title, description, remediation),
		Severity:        strings.ToLower(severity),
		Confidence:      strings.ToLower(confidence),
		Status:          strings.ToLower(status),
		Remediation:     remediation,
		CWEID:           cwe,
		SourceFile:      sourceFile,
		Tags:            tags,
		Request:         request,
		Response:        response,
		FindingHash:     findingHash,
		FoundAt:         time.Now().UTC(),
	}

	if err := c.Repo.SaveFindingDirect(ctx, finding); err != nil {
		return PersistResult{
			Message: fmt.Sprintf("failed to save finding: %v", err),
			IsError: true,
		}
	}

	n := c.Count.Add(1)
	msg := fmt.Sprintf("Saved finding #%d: [%s] %s (hash=%s)", n, severity, title, finding.FindingHash[:12])
	if n >= reportFindingSoftWarn {
		msg += fmt.Sprintf(
			"\n\n[warning] %d findings recorded. Past ~%d is unusual — consider whether you're re-reporting the same bug. "+
				"Hard cap is %d, after which new findings are rejected.",
			n, reportFindingSoftWarn, reportFindingHardCap)
	}
	return PersistResult{
		Message: msg,
		Count:   n,
		Details: map[string]any{
			"severity":     severity,
			"title":        title,
			"total_so_far": n,
		},
	}
}

// PersistResult carries the outcome of PersistFromArgs.
type PersistResult struct {
	Message string         // human-readable status (success or failure)
	Count   int64          // post-save total (0 when IsError)
	Details map[string]any // structured info passed through to tool.Result.Details
	IsError bool
}

// Exported thin wrappers so the verify-before-promote pipeline (pkg/agent) can
// build a promoted Finding from a candidate with exactly the same composition
// and hashing the report_finding tool uses — keeping dedup consistent between a
// directly-reported finding and a verified-then-promoted one.

// HashFinding is the exported form of hashFinding.
func HashFinding(title, severity, sourceFile, url, description string) string {
	return hashFinding(title, severity, sourceFile, url, description)
}

// HashDedupKey is the exported form of hashDedupKey.
func HashDedupKey(key string) string { return hashDedupKey(key) }

// ComposeDescription is the exported form of composeDescription.
func ComposeDescription(title, description, remediation string) string {
	return composeDescription(title, description, remediation)
}

// ExtractHostname is the exported form of extractHostname.
func ExtractHostname(rawURL string) string { return extractHostname(rawURL) }

// Truncate is the exported form of truncate.
func Truncate(s string, max int) string { return truncate(s, max) }

// hashFinding builds a deterministic fingerprint so duplicate calls are
// squashed by SaveFindingDirect's ON CONFLICT handling. Includes a
// normalized description fingerprint so two genuinely different bugs that
// happen to share a title/severity/location aren't collapsed.
func hashFinding(title, severity, sourceFile, url, description string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(title))))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(severity))))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(sourceFile)))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(url)))
	h.Write([]byte{0})
	h.Write([]byte(normalizeDescriptionFingerprint(description)))
	return hex.EncodeToString(h.Sum(nil))
}

// hashDedupKey produces the finding hash when the caller supplies an
// explicit dedup_key. Keeping it through sha256 (rather than using the raw
// string) matches the length/shape of the default hash so downstream
// callers don't have to special-case.
func hashDedupKey(key string) string {
	h := sha256.New()
	h.Write([]byte("dedup-key\x00"))
	h.Write([]byte(strings.ToLower(strings.TrimSpace(key))))
	return hex.EncodeToString(h.Sum(nil))
}

// descWhitespaceRe collapses runs of whitespace to a single space so that
// cosmetic phrasing differences (line wraps, indentation) don't bust the
// dedup hash.
var descWhitespaceRe = regexp.MustCompile(`\s+`)

// normalizeDescriptionFingerprint turns a free-form description into a
// stable short identifier: lowercase, whitespace-collapsed, trimmed to the
// first 128 chars. Short enough to be stable across paraphrase-level noise,
// long enough that two genuinely different bugs with the same title still
// produce different hashes.
func normalizeDescriptionFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = descWhitespaceRe.ReplaceAllString(s, " ")
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func composeDescription(title, description, remediation string) string {
	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n\n")
	b.WriteString(description)
	if strings.TrimSpace(remediation) != "" {
		b.WriteString("\n\nRemediation: ")
		b.WriteString(remediation)
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// maxEvidenceRecords bounds how many http_record UUIDs a single finding may
// link. A well-scoped finding cites a handful; past this a looping model is
// almost certainly over-attaching.
const maxEvidenceRecords = 50

// parseRecordUUIDs normalizes the record_uuids arg into a deduped, bounded,
// non-nil slice of trimmed non-empty UUIDs. The []any / []string coercion is
// delegated to stringSlice; the dedup, maxEvidenceRecords cap, and non-nil
// guarantee (so the DB column matches the prior []string{} when the model
// links no evidence) are finding-specific and stay here.
func parseRecordUUIDs(raw any) []string {
	out := make([]string, 0)
	seen := map[string]struct{}{}
	for _, v := range stringSlice(raw) {
		if v = strings.TrimSpace(v); v == "" || len(out) >= maxEvidenceRecords {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func extractHostname(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rawURL = rawURL[i+3:]
	}
	if i := strings.IndexAny(rawURL, "/?#"); i >= 0 {
		rawURL = rawURL[:i]
	}
	if i := strings.IndexByte(rawURL, ':'); i >= 0 {
		rawURL = rawURL[:i]
	}
	return rawURL
}
