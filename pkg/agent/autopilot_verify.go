package agent

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	oautopilot "github.com/vigolium/vigolium/pkg/olium/autopilot"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	otool "github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/vigtool"
	"go.uber.org/zap"
)

// Durable-autopilot verify-before-promote. After the operator loop returns in
// shadow/enforced mode, each proposed candidate is re-checked by a FRESH-context
// skeptic verifier (its own engine + its own transcript, read-only investigation
// tools) against a per-class evidence gate. Only candidates whose verdict is
// "confirmed" are promoted into real findings. Legacy runs never reach this.

// defaultVerifyConcurrency bounds how many candidate verifiers run at once,
// mirroring the swarm triage default so provider load stays comparable.
const defaultVerifyConcurrency = 3

// maxVerifyTurns caps each per-candidate skeptic engine — enough to replay a
// couple of requests and poll OAST, not enough to wander.
const maxVerifyTurns = 16

// verifyPassBudget bounds the whole verify-before-promote pass. It is applied to
// a context DETACHED from the operator's --max-duration deadline (see
// VerifyCandidates), so a long operator phase can't leave verification running
// under an already-expired context — which silently failed every status update
// and promotion. Generous because each per-candidate verifier is separately
// bounded (maxVerifyTurns + an 8-minute per-candidate timeout) and up to
// defaultVerifyConcurrency run at once.
const verifyPassBudget = 15 * time.Minute

// VerifyCandidatesConfig configures a verify-before-promote pass.
type VerifyCandidatesConfig struct {
	Repo            *database.Repository
	Provider        provider.Provider
	Model           string
	ProjectUUID     string
	ScanUUID        string
	AgenticScanUUID string
	Target          string
	SessionDir      string
	Mode            string // config.AutopilotMode{Shadow,Enforced}
	Concurrency     int    // 0 = defaultVerifyConcurrency
	StreamWriter    io.Writer
}

// VerifyCandidatesResult summarizes a verify pass.
type VerifyCandidatesResult struct {
	Total         int
	Confirmed     int
	Rejected      int
	NeedsEvidence int
	Promoted      int // findings written (confirmed & promotion succeeded)
}

// VerifyCandidates runs the fresh-context verifier over every proposed
// candidate for the run, promoting the confirmed ones. It is a no-op (nil,
// nil) in legacy mode, without a repo/provider, or when there are no proposed
// candidates. Best-effort: an individual verifier failure marks that candidate
// needs_evidence and continues; the pass never fails the whole autopilot run.
func VerifyCandidates(ctx context.Context, cfg VerifyCandidatesConfig) (*VerifyCandidatesResult, error) {
	mode := config.NormalizeAutopilotMode(cfg.Mode)
	if mode == config.AutopilotModeLegacy {
		return nil, nil
	}
	if cfg.Repo == nil || cfg.Provider == nil || cfg.AgenticScanUUID == "" {
		return nil, nil
	}

	// Verify-before-promote is post-halt cleanup. Detach from the operator's
	// --max-duration deadline and give the pass its own budget: a long operator
	// phase must NOT leave verification (its verifier engines AND its final
	// status-update/promotion writes) running under an already-expired context.
	// WithoutCancel keeps request-scoped values while dropping the parent's
	// cancellation/deadline; the fresh timeout re-bounds the pass.
	ctx = context.WithoutCancel(ctx)
	ctx, cancel := context.WithTimeout(ctx, verifyPassBudget)
	defer cancel()

	candidates, err := cfg.Repo.ListCandidates(ctx, cfg.AgenticScanUUID, database.CandidateStatusProposed)
	if err != nil {
		return nil, fmt.Errorf("verify: list candidates: %w", err)
	}
	if len(candidates) == 0 {
		return &VerifyCandidatesResult{}, nil
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = defaultVerifyConcurrency
	}
	if concurrency > len(candidates) {
		concurrency = len(candidates)
	}

	if cfg.StreamWriter != nil {
		_, _ = fmt.Fprintf(cfg.StreamWriter, "[verify] verifying %d proposed candidate(s) with %d skeptic verifier(s)\n",
			len(candidates), concurrency)
	}

	verdicts := make([]candidateVerdict, len(candidates))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range candidates {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				verdicts[i] = candidateVerdict{verdict: database.CandidateStatusNeedsEvidence, reason: "verification cancelled"}
				return
			}
			verdicts[i] = verifyOneCandidate(ctx, cfg, candidates[i], i+1, mode)
		}()
	}
	wg.Wait()

	// Apply verdicts + promotions serially (writes to the DB), so counts and
	// promotion are deterministic and lock-free.
	res := &VerifyCandidatesResult{Total: len(candidates)}
	for i, cand := range candidates {
		v := verdicts[i]
		switch v.verdict {
		case database.CandidateStatusConfirmed:
			res.Confirmed++
			findingID, perr := promoteCandidate(ctx, cfg, cand, v, mode)
			if perr != nil {
				zap.L().Warn("verify: promotion failed", zap.String("candidate", cand.UUID), zap.Error(perr))
				_ = cfg.Repo.UpdateCandidateStatus(ctx, cand.UUID, database.CandidateStatusConfirmed, v.reason+" (promotion failed: "+perr.Error()+")", 0)
				continue
			}
			res.Promoted++
			if uerr := cfg.Repo.UpdateCandidateStatus(ctx, cand.UUID, database.CandidateStatusConfirmed, v.reason, findingID); uerr != nil {
				zap.L().Warn("verify: candidate status update failed", zap.String("candidate", cand.UUID), zap.Error(uerr))
			}
			if cfg.StreamWriter != nil {
				_, _ = fmt.Fprintf(cfg.StreamWriter, "[verify] CONFIRMED [%s] %s -> finding #%d\n", cand.Severity, cand.Title, findingID)
			}
		case database.CandidateStatusRejected:
			res.Rejected++
			if uerr := cfg.Repo.UpdateCandidateStatus(ctx, cand.UUID, database.CandidateStatusRejected, v.reason, 0); uerr != nil {
				zap.L().Warn("verify: candidate status update failed", zap.String("candidate", cand.UUID), zap.Error(uerr))
			}
			if cfg.StreamWriter != nil {
				_, _ = fmt.Fprintf(cfg.StreamWriter, "[verify] rejected [%s] %s — %s\n", cand.Severity, cand.Title, truncateReason(v.reason))
			}
		default:
			res.NeedsEvidence++
			if uerr := cfg.Repo.UpdateCandidateStatus(ctx, cand.UUID, database.CandidateStatusNeedsEvidence, v.reason, 0); uerr != nil {
				zap.L().Warn("verify: candidate status update failed", zap.String("candidate", cand.UUID), zap.Error(uerr))
			}
			if cfg.StreamWriter != nil {
				_, _ = fmt.Fprintf(cfg.StreamWriter, "[verify] needs-evidence [%s] %s — %s\n", cand.Severity, cand.Title, truncateReason(v.reason))
			}
		}
	}

	if cfg.StreamWriter != nil {
		_, _ = fmt.Fprintf(cfg.StreamWriter, "[verify] done: %d confirmed (%d promoted), %d rejected, %d needs-evidence\n",
			res.Confirmed, res.Promoted, res.Rejected, res.NeedsEvidence)
	}
	return res, nil
}

// candidateVerdict is the parsed outcome of one verifier engine run.
type candidateVerdict struct {
	verdict string // confirmed | rejected | needs_evidence
	reason  string
	grade   string // strong | moderate | weak
}

// verifyOneCandidate runs a single fresh-context skeptic engine over one
// candidate and returns its structured verdict. A verifier that never submits a
// verdict (engine exhausted turns, provider error) defaults to needs_evidence —
// the conservative choice, since verify-before-promote must never confirm
// without an explicit judgment.
func verifyOneCandidate(ctx context.Context, cfg VerifyCandidatesConfig, cand *database.AgentFindingCandidate, idx int, mode string) candidateVerdict {
	sink := &verdictSink{}

	tools := otool.NewRegistry()
	otool.RegisterBuiltins(tools, nil)
	sessCtx := &vigtool.SessionsContext{Repo: cfg.Repo, ProjectUUID: cfg.ProjectUUID}
	tools.Register(vigtool.NewQueryRecordsTool(sessCtx))
	tools.Register(vigtool.NewInspectRecordTool(sessCtx))
	tools.Register(vigtool.NewReplayRequestTool(sessCtx))
	tools.Register(vigtool.NewOASTPollTool(sessCtx))
	if cfg.ProjectUUID != "" {
		tools.Register(otool.NewBrowserProbeWithCapture(cfg.Repo, cfg.ProjectUUID))
	}
	tools.Register(newSubmitVerdictTool(sink))

	ecfg := oengine.Config{
		Provider: cfg.Provider,
		Tools:    tools,
		Model:    cfg.Model,
		System:   verifierSystemPrompt,
		MaxTurns: maxVerifyTurns,
		SpillDir: cfg.SessionDir,
	}
	// Each verifier writes its OWN transcript file so concurrent verifiers
	// never interleave into one file (the engine recorder is single-writer).
	if cfg.SessionDir != "" {
		provName := ""
		if cfg.Provider != nil {
			provName = cfg.Provider.Name()
		}
		path := filepath.Join(cfg.SessionDir, fmt.Sprintf("transcript-verify-%d.jsonl", idx))
		if rec, rerr := sessionlog.New(path, sessionlog.Meta{
			SessionID: fmt.Sprintf("%s-verify-%d", cfg.AgenticScanUUID, idx),
			Provider:  provName,
			Model:     cfg.Model,
		}); rerr == nil {
			ecfg.Recorder = rec
		}
	}

	eng := oengine.New(ecfg)
	defer func() { _ = eng.CloseRecorder() }()

	vctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	for ev := range eng.Run(vctx, buildVerifierPrompt(cand)) {
		// Drain the stream; the verdict lands in sink via submit_verdict. We
		// don't render deltas here — the transcript file is the record.
		_ = ev
		if sink.done() {
			// Verdict submitted; let the engine finish its turn but we already
			// have what we need. Keep draining to close the channel cleanly.
			continue
		}
	}

	v, reason, grade, ok := sink.get()
	if !ok {
		return candidateVerdict{
			verdict: database.CandidateStatusNeedsEvidence,
			reason:  "verifier did not submit a verdict (exhausted turns or provider error); not promoting without explicit confirmation",
		}
	}
	return candidateVerdict{verdict: v, reason: reason, grade: grade}
}

// promoteCandidate builds a Finding from a confirmed candidate and saves it,
// returning the new finding id. In enforced mode the finding reuses the
// candidate's dedup hash (there is no direct finding to collide with). In
// shadow mode the direct report_finding already wrote a finding with that
// hash, so the verified finding is given a distinct hash + source tag to
// coexist for FP-rate comparison.
func promoteCandidate(ctx context.Context, cfg VerifyCandidatesConfig, cand *database.AgentFindingCandidate, v candidateVerdict, mode string) (int64, error) {
	findingSource := "autopilot-verified"
	if mode == config.AutopilotModeShadow {
		findingSource = "autopilot-shadow-verified"
	}

	findingHash := promotedFindingHash(cand, mode)

	confidence := cand.Confidence
	if confidence == "" {
		confidence = "firm"
	}

	desc := oautopilot.ComposeDescription(cand.Title, cand.Description, cand.Remediation)
	if strings.TrimSpace(v.reason) != "" {
		desc += "\n\nVerifier verdict: " + v.reason
	}

	finding := &database.Finding{
		ProjectUUID:     cfg.ProjectUUID,
		HTTPRecordUUIDs: cand.RecordUUIDs,
		ScanUUID:        cfg.ScanUUID,
		AgenticScanUUID: cfg.AgenticScanUUID,
		URL:             cand.URL,
		Hostname:        cand.Hostname,
		ModuleID:        "olium-autopilot-verified",
		ModuleName:      "olium autopilot (verified)",
		ModuleType:      "ai-agent",
		FindingSource:   findingSource,
		ModuleShort:     oautopilot.Truncate(cand.Title, 80),
		Description:     desc,
		Severity:        strings.ToLower(cand.Severity),
		Confidence:      strings.ToLower(confidence),
		Status:          database.StatusTriaged,
		Remediation:     cand.Remediation,
		CWEID:           cand.CWEID,
		SourceFile:      cand.SourceFile,
		EvidenceGrade:   v.grade,
		Tags:            cand.Tags,
		Request:         cand.Request,
		Response:        cand.Response,
		FindingHash:     findingHash,
		FoundAt:         time.Now().UTC(),
	}
	if len(finding.HTTPRecordUUIDs) == 0 {
		finding.HTTPRecordUUIDs = []string{}
	}
	if err := cfg.Repo.SaveFindingDirect(ctx, finding); err != nil {
		return 0, err
	}
	return finding.ID, nil
}

// promotedFindingHash resolves the finding_hash for a promoted candidate.
func promotedFindingHash(cand *database.AgentFindingCandidate, mode string) string {
	base := cand.DedupHash
	if base == "" {
		base = oautopilot.HashFinding(cand.Title, cand.Severity, cand.SourceFile, cand.URL, cand.Description)
	}
	if mode == config.AutopilotModeShadow {
		// Distinct from the direct finding so both coexist for comparison.
		return oautopilot.HashDedupKey("shadow-verified\x00" + base)
	}
	return base
}

// --- verifier prompt + evidence gates ---

const verifierSystemPrompt = "You are a skeptical, independent security verifier. A prior agent PROPOSED a vulnerability " +
	"candidate; your job is to CONFIRM or REFUTE it using only the investigation tools you are given (query_records, " +
	"inspect_record, replay_request, oast_poll, browser_probe, and file/shell reads). Default to skepticism: you must " +
	"see evidence that clearly meets the class-specific gate before confirming. Never confirm on the proposer's word " +
	"alone — reproduce the evidence yourself. When you are finished, call submit_verdict exactly once."

// buildVerifierPrompt renders the per-candidate user prompt.
func buildVerifierPrompt(cand *database.AgentFindingCandidate) string {
	var b strings.Builder
	b.WriteString("# Candidate to verify\n\n")
	fmt.Fprintf(&b, "- Title: %s\n", cand.Title)
	fmt.Fprintf(&b, "- Class: %s\n", cand.Class)
	fmt.Fprintf(&b, "- Severity: %s\n", cand.Severity)
	if cand.URL != "" {
		fmt.Fprintf(&b, "- URL: %s\n", cand.URL)
	}
	if cand.SourceFile != "" {
		fmt.Fprintf(&b, "- Source file: %s\n", cand.SourceFile)
	}
	if len(cand.RecordUUIDs) > 0 {
		fmt.Fprintf(&b, "- Linked http_records: %s\n", strings.Join(cand.RecordUUIDs, ", "))
	}
	if len(cand.OASTIDs) > 0 {
		fmt.Fprintf(&b, "- OAST ids: %s\n", strings.Join(cand.OASTIDs, ", "))
	}
	b.WriteString("\n## Proposer's description & verification plan\n\n")
	b.WriteString(cand.Description)
	b.WriteString("\n\n## Evidence gate (you MUST satisfy this to confirm)\n\n")
	b.WriteString(evidenceGate(cand.Class))
	b.WriteString("\n\n## How to respond\n\n")
	b.WriteString("Investigate first (inspect the linked records, replay the attack and a baseline, poll OAST, or drive a browser). ")
	b.WriteString("Then call `submit_verdict` exactly once with verdict = confirmed | rejected | needs_evidence, a one–two sentence " +
		"reason citing the concrete evidence you observed, and evidence_grade = strong | moderate | weak. " +
		"If you cannot obtain the evidence the gate requires, the verdict is rejected or needs_evidence — not confirmed.")
	return b.String()
}

// evidenceGate returns the class-specific confirmation bar the verifier must
// clear. Unknown classes fall through to the general attack-vs-baseline gate.
func evidenceGate(class string) string {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case "idor":
		return "IDOR gate: demonstrate an owner vs non-owner comparison — replay the same access as the legitimate owner AND as a different principal, and show the non-owner obtains data or an action they must not. If you cannot obtain a second principal, or the non-owner is correctly denied, the verdict is rejected or needs_evidence."
	case "xss":
		return "XSS gate: demonstrate script EXECUTION in a browser context — use browser_probe to load the injected page and confirm the payload actually runs (a fired sink / DOM change), not merely that a string is reflected. A reflection that is HTML/JS-encoded or lands in a non-executing context is rejected."
	case "sqli":
		return "SQLi gate: show a paired control that only a SQL context explains — a true vs false boolean condition producing different responses, an error vs no-error pair, or a measurable, repeatable time delta. A generic error or reflected input alone is rejected."
	case "ssrf", "rce":
		return "SSRF/RCE gate: show a UNIQUE out-of-band interaction — oast_poll must return a hit that correlates to this candidate's canary/OAST id. No unique OAST callback that you can tie to this payload means rejected or needs_evidence."
	case "auth":
		return "Auth gate: demonstrate the control is actually bypassed — the protected action succeeds without valid credentials/authorization, and the same action is denied under a correct control. A 401/403 on the attack path is rejected."
	default:
		return "General gate: replay the attack request AND a benign baseline request, and show a security-relevant difference that the attack payload (not normal app behavior) caused. If the difference is explainable by ordinary behavior, the verdict is rejected."
	}
}

func truncateReason(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 140 {
		return s[:139] + "…"
	}
	return s
}
