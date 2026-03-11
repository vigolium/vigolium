package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"go.uber.org/zap"
)

// PipelineRunner orchestrates the multi-phase scanning pipeline with agent checkpoints.
//
// Pipeline phases:
//  0. Source Analysis — agent checkpoint: analyze source code, extract routes, session config, extensions
//  1. Discover — native deparos/spidering (no agent)
//  2. Plan — agent checkpoint: analyze discovery results, output AttackPlan
//  3. Scan — native executor with plan-selected modules (no agent)
//  4. Triage — agent checkpoint: review findings, output TriageResult
//  5. Rescan — native executor with triage follow-ups (loops back to 4, max N rounds)
//  6. Report — structured output from DB (no agent)
type PipelineRunner struct {
	engine *Engine
	repo   *database.Repository
}

// NewPipelineRunner creates a pipeline runner.
func NewPipelineRunner(engine *Engine, repo *database.Repository) *PipelineRunner {
	return &PipelineRunner{
		engine: engine,
		repo:   repo,
	}
}

// Run executes the full pipeline.
func (p *PipelineRunner) Run(ctx context.Context, cfg PipelineConfig) (*PipelineResult, error) {
	start := time.Now()
	result := &PipelineResult{}

	phases := p.resolvePhases(cfg)

	for _, phase := range phases {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if cfg.PhaseCallback != nil {
			cfg.PhaseCallback(phase)
		}

		phaseStart := time.Now()
		var err error

		switch phase {
		case PhaseSourceAnalysis:
			result.SourceAnalysis, err = p.runSourceAnalysis(ctx, cfg)
		case PhaseDiscover:
			err = p.runDiscover(ctx, cfg)
		case PhasePlan:
			result.Plan, err = p.runPlan(ctx, cfg)
		case PhaseScan:
			err = p.runScan(ctx, cfg, result.Plan)
		case PhaseTriage:
			err = p.runTriageLoop(ctx, cfg, result)
		case PhaseReport:
			err = p.runReport(ctx, cfg, result)
		}

		if err != nil {
			zap.L().Error("Pipeline phase failed",
				zap.String("phase", string(phase)),
				zap.Duration("duration", time.Since(phaseStart)),
				zap.Error(err))
			return result, fmt.Errorf("phase %s failed: %w", phase, err)
		}

		result.PhasesRun = append(result.PhasesRun, phase)
		zap.L().Info("Pipeline phase completed",
			zap.String("phase", string(phase)),
			zap.Duration("duration", time.Since(phaseStart)))
	}

	result.Duration = time.Since(start)
	return result, nil
}

// resolvePhases returns the ordered list of phases to run, respecting skip/start-from config.
func (p *PipelineRunner) resolvePhases(cfg PipelineConfig) []PipelinePhase {
	all := AllPipelinePhases()

	// Auto-skip source-analysis when no source path is provided
	if cfg.SourcePath == "" {
		if cfg.SkipPhases == nil {
			cfg.SkipPhases = make(map[PipelinePhase]bool)
		}
		cfg.SkipPhases[PhaseSourceAnalysis] = true
	}

	// Apply start-from: skip phases before the starting phase
	if cfg.StartFrom != "" {
		startIdx := -1
		for i, phase := range all {
			if phase == cfg.StartFrom {
				startIdx = i
				break
			}
		}
		if startIdx > 0 {
			all = all[startIdx:]
		}
	}

	// Filter out skipped phases
	var phases []PipelinePhase
	for _, phase := range all {
		if cfg.SkipPhases != nil && cfg.SkipPhases[phase] {
			zap.L().Debug("Skipping pipeline phase", zap.String("phase", string(phase)))
			continue
		}
		phases = append(phases, phase)
	}

	// Rescan only runs if triage is also running
	hasTriage := false
	for _, phase := range phases {
		if phase == PhaseTriage {
			hasTriage = true
			break
		}
	}
	if !hasTriage {
		var filtered []PipelinePhase
		for _, phase := range phases {
			if phase != PhaseRescan {
				filtered = append(filtered, phase)
			}
		}
		phases = filtered
	}

	return phases
}

// runSourceAnalysis executes phase 0: AI-driven source code analysis.
// Delegates to Engine.RunSourceAnalysis and invokes the pipeline-specific callback.
func (p *PipelineRunner) runSourceAnalysis(ctx context.Context, cfg PipelineConfig) (*SourceAnalysisResult, error) {
	saCfg := SourceAnalysisConfig{
		AgentName:    cfg.AgentName,
		TargetURL:    cfg.TargetURL,
		SourcePath:   cfg.SourcePath,
		Files:        cfg.Files,
		DryRun:       cfg.DryRun,
		ShowPrompt:   cfg.ShowPrompt,
		ScanUUID:     cfg.ScanUUID,
		ProjectUUID:  cfg.ProjectUUID,
		StreamWriter: cfg.StreamWriter,
	}

	saResult, _, err := p.engine.RunSourceAnalysis(ctx, saCfg)
	if err != nil {
		return nil, err
	}

	// Invoke callback so the CLI/server can write extensions and session config to disk
	if saResult != nil && cfg.SourceAnalysisCallback != nil {
		if cbErr := cfg.SourceAnalysisCallback(saResult); cbErr != nil {
			zap.L().Warn("Source analysis callback failed", zap.Error(cbErr))
		}
	}

	return saResult, nil
}

// runDiscover executes phase 1: discovery and spidering.
func (p *PipelineRunner) runDiscover(ctx context.Context, cfg PipelineConfig) error {
	if cfg.DiscoverFunc == nil {
		return fmt.Errorf("no discover function configured")
	}
	return cfg.DiscoverFunc(ctx)
}

// baseAgentOpts builds the common Options fields shared by plan and triage agent calls.
func baseAgentOpts(cfg PipelineConfig, template string) Options {
	opts := Options{
		AgentName:      cfg.AgentName,
		PromptTemplate: template,
		TargetURL:      cfg.TargetURL,
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		Source:         template,
		StreamWriter:   cfg.StreamWriter,
	}
	return opts
}

// runPlan executes phase 2: agent plans attack strategy based on discovery results.
func (p *PipelineRunner) runPlan(ctx context.Context, cfg PipelineConfig) (*AttackPlan, error) {
	opts := baseAgentOpts(cfg, "pipeline-plan")
	if cfg.Focus != "" {
		opts.Append = fmt.Sprintf("## Focus Area\n\n%s", cfg.Focus)
	}

	result, err := p.engine.Run(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("plan agent failed: %w", err)
	}

	if cfg.DryRun {
		fmt.Fprint(os.Stdout, result.RawOutput)
		return nil, nil
	}

	plan, err := ParseAttackPlan(result.RawOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attack plan: %w", err)
	}

	// Validate module tags against registry
	if len(plan.ModuleTags) > 0 {
		resolved := modules.ResolveModuleTags(plan.ModuleTags)
		if len(resolved) == 0 {
			zap.L().Warn("Agent-suggested module tags matched no modules, falling back to all",
				zap.Strings("tags", plan.ModuleTags))
			plan.ModuleTags = nil
		} else {
			zap.L().Info("Attack plan module selection",
				zap.Strings("tags", plan.ModuleTags),
				zap.Int("matchedModules", len(resolved)))
		}
	}

	return plan, nil
}

// runScan executes phase 3: dynamic assessment with plan-selected modules.
func (p *PipelineRunner) runScan(ctx context.Context, cfg PipelineConfig, plan *AttackPlan) error {
	if cfg.ScanFunc == nil {
		return fmt.Errorf("no scan function configured")
	}

	var tags, ids []string
	if plan != nil {
		tags = plan.ModuleTags
		ids = plan.ModuleIDs
	}

	return cfg.ScanFunc(ctx, tags, ids)
}

// runTriageLoop runs the triage phase and optional rescan loop (phases 4-5).
func (p *PipelineRunner) runTriageLoop(ctx context.Context, cfg PipelineConfig, result *PipelineResult) error {
	maxRounds := cfg.MaxRescanRounds
	if maxRounds <= 0 {
		maxRounds = 2
	}

	for round := 0; round <= maxRounds; round++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		triage, err := p.runTriage(ctx, cfg, round)
		if err != nil {
			return fmt.Errorf("triage round %d failed: %w", round, err)
		}

		if cfg.DryRun {
			return nil
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
		if err := p.runRescan(ctx, cfg, triage.FollowUps); err != nil {
			zap.L().Warn("Rescan failed, continuing with triage results",
				zap.Int("round", round+1),
				zap.Error(err))
			break
		}
	}

	return nil
}

// runTriage executes the triage agent checkpoint.
func (p *PipelineRunner) runTriage(ctx context.Context, cfg PipelineConfig, round int) (*TriageResult, error) {
	opts := baseAgentOpts(cfg, "pipeline-triage")
	if round > 0 {
		opts.Append = fmt.Sprintf("## Context\n\nThis is triage round %d (after rescan). Focus on new findings from the latest scan.", round+1)
	}

	result, err := p.engine.Run(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("triage agent failed: %w", err)
	}

	if cfg.DryRun {
		fmt.Fprint(os.Stdout, result.RawOutput)
		return &TriageResult{Verdict: "done"}, nil
	}

	triage, err := ParseTriageResult(result.RawOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse triage result: %w", err)
	}

	return triage, nil
}

// runRescan executes follow-up scans recommended by the triage agent.
func (p *PipelineRunner) runRescan(ctx context.Context, cfg PipelineConfig, followUps []FollowUpScan) error {
	if cfg.ScanFunc == nil {
		return fmt.Errorf("no scan function configured")
	}

	// Aggregate all follow-up module tags and IDs
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

	// If no specific modules requested, use all
	if len(tags) == 0 && len(ids) == 0 {
		zap.L().Debug("Rescan with no specific modules, using all")
	}

	return cfg.ScanFunc(ctx, tags, ids)
}

// runReport executes phase 6: generate structured report from DB.
func (p *PipelineRunner) runReport(ctx context.Context, cfg PipelineConfig, result *PipelineResult) error {
	if p.repo == nil {
		return nil
	}

	counts, err := database.CountFindingsBySeverity(ctx, p.repo.DB(), cfg.ProjectUUID)
	if err != nil {
		zap.L().Debug("Failed to count findings for report", zap.Error(err))
		return nil
	}

	total := 0
	for _, count := range counts {
		total += int(count)
	}
	result.TotalFindings = total
	return nil
}
