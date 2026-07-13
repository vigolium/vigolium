package autopilot

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// newCandidateUUID mints the identity for a proposed candidate row.
func newCandidateUUID() string { return uuid.NewString() }

// The propose_candidate tool mirrors report_finding, but instead of writing a
// finding straight to the DB it records a *candidate* into
// agent_finding_candidates (status=proposed). In enforced mode the operator
// only ever proposes; a fresh-context verifier later grades each candidate and
// promotes the confirmed ones into real findings. This decouples "the operator
// thinks it found X" from "X is a confirmed vulnerability", which is the whole
// point of verify-before-promote. Legacy runs never register this tool.

// candidateClasses is the closed set of coarse vulnerability classes a
// candidate may declare. The verifier picks a per-class evidence gate from
// this, so an unknown value degrades to "other" (attack+baseline gate).
var candidateClasses = []string{"idor", "xss", "sqli", "ssrf", "rce", "auth", "other"}

func validCandidateClass(s string) bool {
	for _, c := range candidateClasses {
		if c == s {
			return true
		}
	}
	return false
}

// CandidateSink is the narrow persistence surface the propose_candidate tool
// needs. *database.Repository does not satisfy it directly (its SaveCandidate
// returns (bool, error) for dedup accounting), so use RepoCandidateSink to
// adapt one. Keeping the interface tiny lets tests swap in a fake.
type CandidateSink interface {
	SaveCandidate(ctx context.Context, cand *database.AgentFindingCandidate) error
}

// repoCandidateSink adapts a *database.Repository to CandidateSink, discarding
// the inserted bool (the tool tracks its own running count).
type repoCandidateSink struct{ repo *database.Repository }

func (r repoCandidateSink) SaveCandidate(ctx context.Context, cand *database.AgentFindingCandidate) error {
	_, err := r.repo.SaveCandidate(ctx, cand)
	return err
}

// RepoCandidateSink wraps a repository as a CandidateSink for the tool. Returns
// nil when repo is nil so callers can gate registration on it.
func RepoCandidateSink(repo *database.Repository) CandidateSink {
	if repo == nil {
		return nil
	}
	return repoCandidateSink{repo: repo}
}

// ProposeCandidateContext pins the scope under which candidates are recorded —
// one instance per autopilot run. SectionUUID (when non-nil) is stamped on each
// candidate so the verifier can attribute a candidate to the section that
// proposed it; the controller repoints it at each rotation.
type ProposeCandidateContext struct {
	Repo            CandidateSink
	ProjectUUID     string
	AgenticScanUUID string
	Target          string       // default URL/host for candidates missing one
	SectionUUID     *string      // current section uuid (nil-safe; repointed on rotation)
	Count           atomic.Int64 // successful proposals this run
}

// NewProposeCandidateTool builds the propose_candidate tool bound to ctx.
func NewProposeCandidateTool(ctx *ProposeCandidateContext) tool.Tool {
	return &proposeCandidateTool{ctx: ctx}
}

// NewShadowReportFindingTool builds a report_finding tool for shadow mode: it
// persists the finding directly (unchanged operator-facing behavior) AND
// mirrors it into a candidate row so the verifier can grade it, enabling an
// apples-to-apples FP-rate comparison between the direct path and the
// verify-before-promote path. The model sees the ordinary report_finding tool.
func NewShadowReportFindingTool(reportCtx *ReportFindingContext, proposeCtx *ProposeCandidateContext) tool.Tool {
	return &shadowReportFindingTool{report: reportCtx, propose: proposeCtx}
}

type shadowReportFindingTool struct {
	report  *ReportFindingContext
	propose *ProposeCandidateContext
}

func (*shadowReportFindingTool) Name() string     { return "report_finding" }
func (*shadowReportFindingTool) Label() string    { return "Record finding" }
func (*shadowReportFindingTool) Category() string { return tool.CategoryVigolium }
func (*shadowReportFindingTool) IsReadOnly() bool { return false }
func (t *shadowReportFindingTool) Description() string {
	return (&reportFindingTool{}).Description()
}
func (t *shadowReportFindingTool) Schema() map[string]any {
	return (&reportFindingTool{}).Schema()
}

func (t *shadowReportFindingTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	res := t.report.PersistFromArgs(ctx, args)
	// Mirror into a candidate row. Best-effort — a mirror failure must never
	// change the operator-visible report_finding outcome. Only mirror when the
	// finding itself persisted, so shadow candidates track real findings.
	if !res.IsError && t.propose != nil {
		_ = t.propose.PersistCandidateFromArgs(ctx, args)
	}
	return tool.Result{
		Content: res.Message,
		IsError: res.IsError,
		Details: res.Details,
	}, nil
}

type proposeCandidateTool struct{ ctx *ProposeCandidateContext }

func (*proposeCandidateTool) Name() string     { return "propose_candidate" }
func (*proposeCandidateTool) Label() string    { return "Propose candidate" }
func (*proposeCandidateTool) Category() string { return tool.CategoryVigolium }
func (*proposeCandidateTool) IsReadOnly() bool { return false }
func (*proposeCandidateTool) Description() string {
	return "Propose a vulnerability CANDIDATE for independent verification. Unlike report_finding, this does not " +
		"record a confirmed finding — a fresh-context skeptic verifier will re-check your evidence and promote only " +
		"the candidates that survive a per-class evidence gate (idor→owner/non-owner compare, xss→browser execution, " +
		"sqli→paired controls, ssrf/rce→unique OAST, else→attack vs baseline). Link the http_records that prove the " +
		"bug via record_uuids and state exactly what you observed. Duplicates are deduped automatically."
}

func (*proposeCandidateTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"title": map[string]any{
				"type":        "string",
				"description": "Short, specific candidate title (e.g., 'IDOR: order 123 readable across tenants').",
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
			"class": map[string]any{
				"type":        "string",
				"enum":        candidateClasses,
				"description": "Coarse vulnerability class — selects the verifier's evidence gate. Use 'other' if none fit.",
			},
			"verification_notes": map[string]any{
				"type":        "string",
				"description": "How you would independently prove this: the exact request(s) to replay, the owner/non-owner accounts, the OAST canary, or the browser step the verifier should reproduce.",
			},
			"remediation": map[string]any{
				"type":        "string",
				"description": "1–2 sentences on how to fix it.",
			},
			"cwe_id": map[string]any{
				"type":        "string",
				"description": "CWE classifier, e.g. 'CWE-639'. Omit if unsure.",
			},
			"source_file": map[string]any{
				"type":        "string",
				"description": "Relative file path for whitebox candidates (e.g., pkg/orders/handler.go:88).",
			},
			"url": map[string]any{
				"type":        "string",
				"description": "Target URL for dynamic candidates.",
			},
			"confidence": map[string]any{
				"type":        "string",
				"enum":        []string{"certain", "firm", "tentative"},
				"description": "How certain you are. Default 'firm'.",
				"default":     "firm",
			},
			"tags": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Classification tags (e.g., [idor, tenant-isolation]).",
			},
			"request": map[string]any{
				"type":        "string",
				"description": "Optional raw HTTP request that triggered the candidate.",
			},
			"response": map[string]any{
				"type":        "string",
				"description": "Optional raw HTTP response demonstrating the issue.",
			},
			"record_uuids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "UUIDs of the http_records that prove this candidate (from query_records / inspect_record / replay_request / web_fetch). Prefer this over pasting large raw request/response text.",
			},
			"oast_ids": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "OAST correlation ids (from oast_mint / oast_poll) that a blind bug's out-of-band callback should match.",
			},
			"dedup_key": map[string]any{
				"type":        "string",
				"description": "Optional explicit dedup identifier. Overrides the default content hash (title + severity + location + description fingerprint).",
			},
		},
		"required": []string{"title", "severity", "description"},
	}
}

func (t *proposeCandidateTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	res := t.ctx.PersistCandidateFromArgs(ctx, args)
	return tool.Result{
		Content: res.Message,
		IsError: res.IsError,
		Details: res.Details,
	}, nil
}

// PersistCandidateFromArgs validates the args, builds an AgentFindingCandidate,
// dedups it (via the shared report_finding hash helpers), persists it, and
// increments the run counter. Shape mirrors ReportFindingContext.PersistFromArgs
// so the two tools behave the same on validation and rate-limit paths.
func (c *ProposeCandidateContext) PersistCandidateFromArgs(ctx context.Context, args map[string]any) PersistResult {
	if c == nil || c.Repo == nil {
		return PersistResult{
			Message: "propose_candidate unavailable: no candidate sink configured for this run",
			IsError: true,
		}
	}

	if current := c.Count.Load(); current >= reportFindingHardCap {
		return PersistResult{
			Message: fmt.Sprintf(
				"propose_candidate rate-limited: %d candidates already recorded for this run (cap=%d). "+
					"This almost always means the loop is double-proposing. Call halt_scan with a summary.",
				current, reportFindingHardCap),
			IsError: true,
		}
	}

	title, _ := args["title"].(string)
	severity, _ := args["severity"].(string)
	description, _ := args["description"].(string)
	if strings.TrimSpace(title) == "" || strings.TrimSpace(severity) == "" || strings.TrimSpace(description) == "" {
		return PersistResult{
			Message: "propose_candidate: title, severity, and description are all required",
			IsError: true,
		}
	}

	confidence, _ := args["confidence"].(string)
	if confidence == "" {
		confidence = "firm"
	}
	class, _ := args["class"].(string)
	class = strings.ToLower(strings.TrimSpace(class))
	if !validCandidateClass(class) {
		class = "other"
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
	verificationNotes, _ := args["verification_notes"].(string)

	var tags []string
	if raw, ok := args["tags"].([]any); ok {
		for _, tg := range raw {
			if s, ok := tg.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	recordUUIDs := parseRecordUUIDs(args["record_uuids"])
	oastIDs := parseRecordUUIDs(args["oast_ids"])

	// Dedup hash uses the raw description (before verification notes are folded
	// in) so re-proposing the same bug with a longer note still collapses.
	var dedupHash string
	if trimmed := strings.TrimSpace(dedupKey); trimmed != "" {
		dedupHash = hashDedupKey(trimmed)
	} else {
		dedupHash = hashFinding(title, severity, sourceFile, url, description)
	}

	// Fold the proposer's own verification plan into the stored description so
	// the verifier sees exactly how the operator intended to prove the bug.
	storedDesc := description
	if strings.TrimSpace(verificationNotes) != "" {
		storedDesc = description + "\n\nProposer verification notes: " + strings.TrimSpace(verificationNotes)
	}

	sectionUUID := ""
	if c.SectionUUID != nil {
		sectionUUID = *c.SectionUUID
	}

	cand := &database.AgentFindingCandidate{
		UUID:            newCandidateUUID(),
		AgenticScanUUID: c.AgenticScanUUID,
		ProjectUUID:     c.ProjectUUID,
		SectionUUID:     sectionUUID,
		Title:           title,
		Severity:        strings.ToLower(severity),
		Description:     storedDesc,
		Remediation:     remediation,
		CWEID:           cwe,
		SourceFile:      sourceFile,
		URL:             url,
		Hostname:        hostname,
		Confidence:      strings.ToLower(confidence),
		Class:           class,
		Status:          database.CandidateStatusProposed,
		RecordUUIDs:     recordUUIDs,
		OASTIDs:         oastIDs,
		Request:         request,
		Response:        response,
		DedupHash:       dedupHash,
		Tags:            tags,
	}

	if err := c.Repo.SaveCandidate(ctx, cand); err != nil {
		return PersistResult{
			Message: fmt.Sprintf("failed to save candidate: %v", err),
			IsError: true,
		}
	}

	n := c.Count.Add(1)
	msg := fmt.Sprintf("Proposed candidate #%d: [%s/%s] %s (hash=%s) — awaiting verification",
		n, severity, class, title, dedupHash[:12])
	if n >= reportFindingSoftWarn {
		msg += fmt.Sprintf(
			"\n\n[warning] %d candidates proposed. Past ~%d is unusual — consider whether you're re-proposing the same bug.",
			n, reportFindingSoftWarn)
	}
	return PersistResult{
		Message: msg,
		Count:   n,
		Details: map[string]any{
			"severity": severity,
			"class":    class,
			"title":    title,
			"proposed": n,
		},
	}
}
