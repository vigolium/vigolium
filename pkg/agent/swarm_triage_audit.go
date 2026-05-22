package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/database"

	"go.uber.org/zap"
)

func (s *SwarmRunner) runTriageLoop(ctx context.Context, cfg SwarmConfig, agenticScan *database.AgenticScan, result *SwarmResult, sessionDir string, extensionDir string, checkpoint *SwarmCheckpoint, extensionRenames map[string]string, completedPhases []string) error {
	// Determine triage resume point from checkpoint
	triageResumeRound := 0
	triageFindingFloor := int64(0)
	if checkpoint != nil && checkpoint.TriageRound > 0 {
		triageResumeRound = checkpoint.TriageRound
		triageFindingFloor = checkpoint.LastFindingID
		zap.L().Info("Resuming triage from checkpoint",
			zap.Int("resume_round", triageResumeRound),
			zap.Int64("finding_floor", triageFindingFloor))
	}

	triageCfg := TriageLoopConfig{
		Engine:                    s.engine,
		Repository:                s.repo,
		AgentName:                 cfg.AgentName,
		PromptTemplate:            SwarmPromptTriage,
		TargetURL:                 agenticScan.TargetURL,
		Hostname:                  hostnameFromURL(agenticScan.TargetURL),
		SourcePath:                cfg.SourcePath,
		Instruction:               cfg.Instruction,
		DryRun:                    cfg.DryRun,
		ShowPrompt:                cfg.ShowPrompt,
		ScanUUID:                  cfg.ScanUUID,
		ProjectUUID:               cfg.ProjectUUID,
		AgenticScanUUID:           agenticScan.UUID,
		StreamWriter:              cfg.StreamWriter,
		Verbose:                   cfg.Verbose,
		MaxRounds:                 cfg.MaxIterations,
		MaxFindingsPerTriageBatch: 25,
		ResumeFromRound:           triageResumeRound,
		ProgressCallback:          cfg.ProgressCallback,
		ScanFunc:                  cfg.ScanFunc,
		SessionDir:                sessionDir,
		ExtensionDir:              extensionDir,
		InitialFindingIDFloor:     triageFindingFloor,
		OnRescan: func() {
			s.emitPhase(cfg, SwarmPhaseRescan)
			agenticScan.CurrentPhase = SwarmPhaseRescan
			s.persistPhase(ctx, agenticScan)
			// Invalidate context cache — rescan may produce new findings
			if s.engine != nil {
				s.engine.InvalidateContextCache()
			}
		},
		OnTriageRoundComplete: func(round int) {
			if cpErr := s.writeSwarmCheckpoint(sessionDir, cfg.ProjectUUID, completedPhases, agenticScan.TargetURL, result.TotalRecords, result.SwarmPlan, extensionDir, round+1, extensionRenames, result, swarmRecordStats{}); cpErr != nil {
				zap.L().Warn("Failed to write checkpoint after triage round", zap.Int("round", round), zap.Error(cpErr))
			}
		},
	}

	loopResult, err := RunTriageLoop(ctx, triageCfg)
	if err != nil {
		return err
	}

	result.TriageResults = loopResult.TriageResults
	result.Confirmed += loopResult.Confirmed
	result.FalsePositives += loopResult.FalsePositives
	result.Iterations = len(loopResult.TriageResults)

	// Store last triage result in agent run record
	if len(loopResult.TriageResults) > 0 {
		lastTriage := loopResult.TriageResults[len(loopResult.TriageResults)-1]
		triageJSON, _ := json.Marshal(lastTriage)
		agenticScan.TriageResult = string(triageJSON)
	}

	return nil
}

// runSASTReview spawns a sub-agent to review SAST findings and validate extracted routes.
// It queries SAST findings from the database, formats them for the agent, and parses
// the response as a SourceAnalysisResult (validated routes + optional extensions).
func (s *SwarmRunner) runCodeAudit(ctx context.Context, cfg SwarmConfig, targetURL string, sessionDir string, sourceAnalysisNotes string, reuseExploreSession bool) (int, error) {
	if s.repo == nil {
		return 0, fmt.Errorf("code audit skipped: no database repository")
	}

	hostname := hostnameFromURL(targetURL)

	// Build extra context for the prompt
	extra := map[string]string{
		"TargetURL": targetURL,
		"Hostname":  hostname,
	}

	// Olium runs each phase in a fresh engine — no session reuse — so the
	// source analysis notes are passed as extra context when available.
	_ = reuseExploreSession
	if sourceAnalysisNotes != "" {
		extra["SourceAnalysisContext"] = sourceAnalysisNotes
	}

	// Query existing routes from DB to give the agent endpoint context
	if hostname != "" {
		dbRecords, recErr := s.repo.GetRecordsByHostname(ctx, cfg.ProjectUUID, hostname, 100)
		if recErr == nil && len(dbRecords) > 0 {
			var rs strings.Builder
			for i, rec := range dbRecords {
				if i >= 100 {
					fmt.Fprintf(&rs, "\n... and %d more routes", len(dbRecords)-100)
					break
				}
				fmt.Fprintf(&rs, "- %s %s\n", rec.Method, rec.URL)
			}
			extra["DiscoveredRoutes"] = rs.String()
		}
	}

	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: SwarmPromptCodeAudit,
		TargetURL:      targetURL,
		Hostname:       hostname,
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		Verbose:        cfg.Verbose,
	}

	agentResult, runErr := s.engine.RunWithExtra(ctx, opts, extra)
	if runErr != nil {
		return 0, fmt.Errorf("code audit agent failed: %w", runErr)
	}

	// Save prompt and output to session dir
	writePromptToSessionDir(sessionDir, "code-audit-prompt.md", agentResult.RenderedPrompt)
	if sessionDir != "" && agentResult.RawOutput != "" {
		writeSessionArtifact(filepath.Join(sessionDir, "code-audit-output.md"), []byte(agentResult.RawOutput))
	}

	if cfg.DryRun {
		return 0, nil
	}

	// Parse findings from agent output
	findings, parseErr := parsing.ParseFindings(agentResult.RawOutput)
	if parseErr != nil {
		zap.L().Warn("Failed to parse code audit findings", zap.Error(parseErr))
		return 0, nil
	}

	if len(findings) == 0 {
		zap.L().Info("Code audit produced no findings")
		return 0, nil
	}

	// Save findings to database
	saved, skipped, ingestErr := s.engine.ingestFindings(ctx, findings, opts)
	if ingestErr != nil {
		return saved, fmt.Errorf("failed to ingest code audit findings: %w", ingestErr)
	}

	zap.L().Info("Code audit completed",
		zap.Int("findings", len(findings)),
		zap.Int("saved", saved),
		zap.Int("skipped", skipped))

	return saved, nil
}
