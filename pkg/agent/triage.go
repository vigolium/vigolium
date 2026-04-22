package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// TriageLoopConfig configures a shared triage+rescan loop used by both Pipeline and Swarm.
type TriageLoopConfig struct {
	Engine     *Engine
	Repository *database.Repository // optional: used for early exit on high-confidence findings

	// Agent options for triage calls
	AgentName      string
	PromptTemplate string // e.g. "pipeline-triage" or "agent-swarm-triage"
	TargetURL      string
	Hostname       string
	SourcePath     string
	Files          []string
	Instruction    string
	SessionKey     string // pool session key (triage reuses the same session across rounds)
	DryRun          bool
	ShowPrompt      bool
	ScanUUID        string
	ProjectUUID     string
	AgenticScanUUID string // when set, triage verdicts are written back to Finding.Status
	StreamWriter    io.Writer

	// Loop control
	MaxRounds                 int
	MaxFindingsPerTriageBatch int // if >0, split findings into batches of this size for triage
	MaxFindingsPerRound       int // max findings loaded per triage round; 0 = default 5000
	ResumeFromRound           int // skip triage rounds before this (0 = start from beginning)
	ProgressCallback          func(ProgressEvent)
	InitialFindingIDFloor     int64 // when >0, only findings newer than this ID are triaged in follow-up rounds

	// Scan callback for rescans
	ScanFunc ScanFunc

	// Session artifacts (optional)
	SessionDir   string
	ExtensionDir string // extension dir from the initial scan, carried into rescans

	// OnRescan is called before each rescan phase starts (optional).
	OnRescan func()

	// OnTriageRoundComplete is called after each triage round completes (optional).
	// The round number (0-indexed) is passed so callers can update checkpoints.
	OnTriageRoundComplete func(round int)
}

// TriageLoopResult holds the accumulated results from a triage+rescan loop.
type TriageLoopResult struct {
	TriageResults  []*TriageResult
	Confirmed      int
	FalsePositives int
	RescanRounds   int
}

// RunTriageLoop executes the triage agent in a loop, optionally rescanning based on the
// agent's verdict. This is the shared implementation used by both Pipeline and Swarm.
func RunTriageLoop(ctx context.Context, cfg TriageLoopConfig) (*TriageLoopResult, error) {
	maxRounds := cfg.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 2
	}

	result := &TriageLoopResult{}

	// Early exit: if all findings have "certain" confidence, skip triage and auto-confirm
	if cfg.Repository != nil && cfg.ProjectUUID != "" {
		findings, findErr := database.NewFindingsQueryBuilder(cfg.Repository.DB(), database.QueryFilters{
			ProjectUUID: cfg.ProjectUUID,
			Limit:       500,
		}).Execute(ctx)
		if findErr == nil && len(findings) > 0 {
			allCertain := true
			for _, f := range findings {
				if f.Confidence != "certain" {
					allCertain = false
					break
				}
			}
			if allCertain {
				zap.L().Info("All findings have 'certain' confidence, skipping triage",
					zap.Int("count", len(findings)))
				result.Confirmed = len(findings)
				return result, nil
			}
		}
	}

	startRound := cfg.ResumeFromRound
	currentFindingFloor := cfg.InitialFindingIDFloor
	if startRound > 0 {
		zap.L().Info("Resuming triage loop from round",
			zap.Int("resume_from", startRound))
	}

	for round := startRound; round <= maxRounds; round++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Determine finding batches for this round
		var findingBatches [][]int64 // nil means single unbatched call
		if cfg.MaxFindingsPerTriageBatch > 0 && cfg.Repository != nil && cfg.ProjectUUID != "" {
			findingsLimit := cfg.MaxFindingsPerRound
			if findingsLimit <= 0 {
				findingsLimit = 5000
			}
			roundFindings, findErr := database.NewFindingsQueryBuilder(cfg.Repository.DB(), database.QueryFilters{
				ProjectUUID:    cfg.ProjectUUID,
				FindingIDAfter: currentFindingFloor,
				Limit:          findingsLimit,
			}).Execute(ctx)
			if findErr == nil && len(roundFindings) > cfg.MaxFindingsPerTriageBatch {
				for i := 0; i < len(roundFindings); i += cfg.MaxFindingsPerTriageBatch {
					end := i + cfg.MaxFindingsPerTriageBatch
					if end > len(roundFindings) {
						end = len(roundFindings)
					}
					batch := make([]int64, 0, end-i)
					for _, f := range roundFindings[i:end] {
						batch = append(batch, f.ID)
					}
					findingBatches = append(findingBatches, batch)
				}
				zap.L().Info("Splitting triage into batches",
					zap.Int("findings", len(roundFindings)),
					zap.Int("batchSize", cfg.MaxFindingsPerTriageBatch),
					zap.Int("batches", len(findingBatches)))
			}
		}

		// merged holds the combined triage result across batches (or the single result)
		merged := &TriageResult{Verdict: "done"}

		numBatches := len(findingBatches)
		if numBatches == 0 {
			numBatches = 1 // single unbatched call
		}

		for batchIdx := 0; batchIdx < numBatches; batchIdx++ {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}

			// Build triage agent options
			triageSessionID := uuid.New().String()
			opts := Options{
				AgentName:      cfg.AgentName,
				PromptTemplate: cfg.PromptTemplate,
				TargetURL:      cfg.TargetURL,
				Hostname:       cfg.Hostname,
				SourcePath:     cfg.SourcePath,
				Files:          cfg.Files,
				Instruction:    cfg.Instruction,
				SessionKey:     cfg.SessionKey,
				SessionID:      triageSessionID,
				DryRun:         cfg.DryRun,
				ShowPrompt:     cfg.ShowPrompt,
				ScanUUID:       cfg.ScanUUID,
				ProjectUUID:    cfg.ProjectUUID,
				Source:         cfg.PromptTemplate,
				StreamWriter:   cfg.StreamWriter,
			}

			var appendParts []string
			if round > 0 {
				appendParts = append(appendParts, fmt.Sprintf("## Context\n\nThis is triage round %d (after rescan). Focus on new findings from the latest scan.", round+1))
			}
			if currentFindingFloor > 0 {
				appendParts = append(appendParts, fmt.Sprintf("## Delta Scope\n\nReview only findings with id > %d. Older findings were already triaged in previous rounds.", currentFindingFloor))
			}
			if findingBatches != nil {
				ids := findingBatches[batchIdx]
				idStrs := make([]string, len(ids))
				for i, id := range ids {
					idStrs[i] = fmt.Sprintf("%d", id)
				}
				appendParts = append(appendParts,
					fmt.Sprintf("## Batch %d/%d — Review only these findings: %s",
						batchIdx+1, len(findingBatches), strings.Join(idStrs, ", ")))
			}
			if len(appendParts) > 0 {
				opts.Append = strings.Join(appendParts, "\n\n")
			}

			var agentResult *Result
			const maxTriageRetries = 3
			for triageAttempt := 1; triageAttempt <= maxTriageRetries; triageAttempt++ {
				var runErr error
				agentResult, runErr = cfg.Engine.Run(ctx, opts)
				if runErr == nil {
					break
				}
				if isRetryableAgentError(ctx, runErr) && triageAttempt < maxTriageRetries {
					zap.L().Warn("triage agent failed (retryable), will retry",
						zap.Int("round", round),
						zap.Int("batch", batchIdx+1),
						zap.Int("attempt", triageAttempt),
						zap.Error(runErr))
					continue
				}
				return result, fmt.Errorf("triage round %d batch %d failed: %w", round, batchIdx+1, runErr)
			}

			triagePhase := fmt.Sprintf("%s-round%d", SwarmPhaseTriage, round)
			if findingBatches != nil {
				triagePhase = fmt.Sprintf("%s-round%d-batch%d", SwarmPhaseTriage, round, batchIdx+1)
			}
			WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
				SessionID: triageSessionID,
				Phase:     triagePhase,
				AgentName: cfg.AgentName,
				Timestamp: time.Now(),
			})

			// Save rendered prompt and raw output to session dir
			batchSuffix := ""
			if findingBatches != nil {
				batchSuffix = fmt.Sprintf("-batch%d", batchIdx+1)
			}
			writePromptToSessionDir(cfg.SessionDir, fmt.Sprintf("triage-%d%s-prompt.md", round, batchSuffix), agentResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, fmt.Sprintf("triage-%d%s-output.md", round, batchSuffix), agentResult.RawOutput)

			if cfg.DryRun {
				_, _ = fmt.Fprint(os.Stdout, agentResult.RawOutput)
				if batchIdx == numBatches-1 {
					return result, nil
				}
				continue
			}

			triage, err := parsing.ParseTriageResult(agentResult.RawOutput)
			if err != nil {
				zap.L().Warn("Failed to parse triage result in batch, skipping batch",
					zap.Int("batch", batchIdx+1), zap.Error(err))
				continue
			}

			// Merge batch result into the combined triage
			merged.Confirmed = append(merged.Confirmed, triage.Confirmed...)
			merged.FalsePositives = append(merged.FalsePositives, triage.FalsePositives...)
			merged.FollowUps = append(merged.FollowUps, triage.FollowUps...)
			if triage.Verdict == "rescan" {
				merged.Verdict = "rescan"
			}
			if triage.Notes != "" {
				if merged.Notes != "" {
					merged.Notes += "\n"
				}
				merged.Notes += triage.Notes
			}
		}

		result.TriageResults = append(result.TriageResults, merged)
		result.Confirmed += len(merged.Confirmed)
		result.FalsePositives += len(merged.FalsePositives)

		// Write triage verdicts back to Finding.Status. Confirmed → triaged,
		// false positives → false_positive. Findings without a finding_hash
		// (older agents not echoing it back) are left as-is for manual triage.
		if cfg.Repository != nil {
			writeBackTriageVerdicts(ctx, cfg.Repository, cfg.AgenticScanUUID, merged)
		}

		if cfg.ProgressCallback != nil {
			cfg.ProgressCallback(ProgressEvent{
				Phase:        "triage",
				SubPhase:     "round",
				Current:      round + 1,
				Total:        maxRounds + 1,
				FindingCount: result.Confirmed,
				Message:      fmt.Sprintf("triage round %d: %d confirmed, %d false positives", round+1, len(merged.Confirmed), len(merged.FalsePositives)),
			})
		}

		// Notify caller that this triage round completed (for checkpoint persistence)
		if cfg.OnTriageRoundComplete != nil {
			cfg.OnTriageRoundComplete(round)
		}

		if merged.Verdict != "rescan" || len(merged.FollowUps) == 0 || round >= maxRounds {
			zap.L().Info("Triage complete",
				zap.String("verdict", merged.Verdict),
				zap.Int("round", round),
				zap.Int("confirmed", len(merged.Confirmed)),
				zap.Int("falsePositives", len(merged.FalsePositives)))
			break
		}

		// Run rescan with follow-up targets
		zap.L().Info("Triage requested rescan",
			zap.Int("round", round+1),
			zap.Int("followUps", len(merged.FollowUps)))

		result.RescanRounds++

		if cfg.ScanFunc != nil {
			if cfg.OnRescan != nil {
				cfg.OnRescan()
			}

			req := aggregateFollowUps(merged.FollowUps)
			req.ExtensionDir = cfg.ExtensionDir // carry extensions from initial scan into rescans
			if cfg.Repository != nil && cfg.ProjectUUID != "" {
				currentFindingFloor = currentMaxFindingID(ctx, cfg.Repository, cfg.ProjectUUID)
			}
			if err := cfg.ScanFunc(ctx, req); err != nil {
				zap.L().Error("Rescan failed, continuing with triage results",
					zap.Int("round", round+1),
					zap.Error(err))
				break
			}
		}
	}

	return result, nil
}

// aggregateFollowUps collects module tags, IDs, and target URLs from triage follow-ups
// into a single ScanRequest. Target URLs are preserved so the rescan can restrict
// scanning to only the endpoints the triage agent identified.
func aggregateFollowUps(followUps []FollowUpScan) ScanRequest {
	tagSet := make(map[string]bool)
	idSet := make(map[string]bool)
	urlSet := make(map[string]bool)
	for _, fu := range followUps {
		for _, t := range fu.ModuleTags {
			tagSet[t] = true
		}
		for _, id := range fu.ModuleIDs {
			idSet[id] = true
		}
		// Collect explicit target URLs from follow-ups
		for _, u := range fu.TargetURLs {
			urlSet[u] = true
		}
		// Also use the follow-up's own URL if present
		if fu.URL != "" {
			urlSet[fu.URL] = true
		}
	}

	var tags []string
	for t := range tagSet {
		tags = append(tags, t)
	}
	var ids []string
	for id := range idSet {
		ids = append(ids, id)
	}
	var targetURLs []string
	for u := range urlSet {
		targetURLs = append(targetURLs, u)
	}

	if len(tags) == 0 && len(ids) == 0 {
		zap.L().Debug("Rescan with no specific modules, using all")
	}

	return ScanRequest{
		ModuleTags: tags,
		ModuleIDs:  ids,
		TargetURLs: targetURLs,
		IsRescan:   true,
	}
}

// writeBackTriageVerdicts persists the triage agent's classifications back to
// Finding.Status. Confirmed findings move draft → triaged; false positives move
// draft → false_positive. Skips entries with empty finding_hash and logs any
// hashes the agent emitted but that didn't match a row.
func writeBackTriageVerdicts(ctx context.Context, repo *database.Repository, agenticScanUUID string, merged *TriageResult) {
	if merged == nil {
		return
	}
	apply := func(items []TriagedFinding, status string) {
		for _, t := range items {
			if t.FindingHash == "" {
				continue
			}
			rows, err := repo.UpdateFindingStatusByHash(ctx, agenticScanUUID, t.FindingHash, status)
			if err != nil {
				zap.L().Warn("triage writeback failed",
					zap.String("finding_hash", t.FindingHash),
					zap.String("status", status),
					zap.Error(err))
				continue
			}
			if rows == 0 {
				zap.L().Debug("triage writeback: no matching finding",
					zap.String("finding_hash", t.FindingHash),
					zap.String("agentic_scan_uuid", agenticScanUUID))
			}
		}
	}
	apply(merged.Confirmed, database.StatusTriaged)
	apply(merged.FalsePositives, database.StatusFalsePositive)
}

func currentMaxFindingID(ctx context.Context, repo *database.Repository, projectUUID string) int64 {
	if repo == nil || projectUUID == "" {
		return 0
	}
	var maxID int64
	if err := repo.DB().NewSelect().
		Model((*database.Finding)(nil)).
		ColumnExpr("COALESCE(MAX(id), 0)").
		Where("project_uuid = ?", projectUUID).
		Scan(ctx, &maxID); err != nil {
		zap.L().Debug("Failed to query current max finding id", zap.Error(err))
		return 0
	}
	return maxID
}
