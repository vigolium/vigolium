package agent

import (
	"context"
	"fmt"
	"io"
	"os"

	"go.uber.org/zap"
)

// TriageLoopConfig configures a shared triage+rescan loop used by both Pipeline and Swarm.
type TriageLoopConfig struct {
	Engine *Engine

	// Agent options for triage calls
	AgentName      string
	AgentACPCmd    string
	PromptTemplate string // e.g. "pipeline-triage" or "agent-swarm-triage"
	TargetURL      string
	Hostname       string
	SourcePath     string
	Files          []string
	Instruction    string
	DryRun         bool
	ShowPrompt     bool
	ScanUUID       string
	ProjectUUID    string
	StreamWriter   io.Writer

	// Loop control
	MaxRounds int

	// Scan callback for rescans
	ScanFunc ScanFunc

	// Session artifacts (optional)
	SessionDir string

	// OnRescan is called before each rescan phase starts (optional).
	OnRescan func()
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

	for round := 0; round <= maxRounds; round++ {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Build triage agent options
		opts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: cfg.PromptTemplate,
			TargetURL:      cfg.TargetURL,
			Hostname:       cfg.Hostname,
			SourcePath:     cfg.SourcePath,
			Files:          cfg.Files,
			Instruction:    cfg.Instruction,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         cfg.PromptTemplate,
			StreamWriter:   cfg.StreamWriter,
		}

		if round > 0 {
			opts.Append = fmt.Sprintf("## Context\n\nThis is triage round %d (after rescan). Focus on new findings from the latest scan.", round+1)
		}

		agentResult, err := cfg.Engine.Run(ctx, opts)
		if err != nil {
			return result, fmt.Errorf("triage round %d failed: %w", round, err)
		}

		// Save rendered prompt and raw output to session dir
		writePromptToSessionDir(cfg.SessionDir, fmt.Sprintf("prompt-triage-%d.md", round), agentResult.RenderedPrompt)
		writePromptToSessionDir(cfg.SessionDir, fmt.Sprintf("triage-output-%d.md", round), agentResult.RawOutput)

		if cfg.DryRun {
			_, _ = fmt.Fprint(os.Stdout, agentResult.RawOutput)
			return result, nil
		}

		triage, err := ParseTriageResult(agentResult.RawOutput)
		if err != nil {
			zap.L().Warn("Failed to parse triage result, treating as done", zap.Error(err))
			return result, nil
		}

		result.TriageResults = append(result.TriageResults, triage)
		result.Confirmed += len(triage.Confirmed)
		result.FalsePositives += len(triage.FalsePositives)

		if triage.Verdict != "rescan" || len(triage.FollowUps) == 0 || round >= maxRounds {
			zap.L().Info("Triage complete",
				zap.String("verdict", triage.Verdict),
				zap.Int("round", round),
				zap.Int("confirmed", len(triage.Confirmed)),
				zap.Int("falsePositives", len(triage.FalsePositives)))
			break
		}

		// Run rescan with follow-up targets
		zap.L().Info("Triage requested rescan",
			zap.Int("round", round+1),
			zap.Int("followUps", len(triage.FollowUps)))

		result.RescanRounds++

		if cfg.ScanFunc != nil {
			if cfg.OnRescan != nil {
				cfg.OnRescan()
			}

			req := aggregateFollowUps(triage.FollowUps)
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

// aggregateFollowUps collects module tags and IDs from triage follow-ups into a single ScanRequest.
func aggregateFollowUps(followUps []FollowUpScan) ScanRequest {
	tagSet := make(map[string]bool)
	idSet := make(map[string]bool)
	for _, fu := range followUps {
		for _, t := range fu.ModuleTags {
			tagSet[t] = true
		}
		for _, id := range fu.ModuleIDs {
			idSet[id] = true
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

	if len(tags) == 0 && len(ids) == 0 {
		zap.L().Debug("Rescan with no specific modules, using all")
	}

	return ScanRequest{
		ModuleTags: tags,
		ModuleIDs:  ids,
		IsRescan:   true,
	}
}
