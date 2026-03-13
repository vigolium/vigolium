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

// Prompt template constants for the pipeline mode.
const (
	PipelinePromptPlan   = "pipeline-plan"
	PipelinePromptTriage = "pipeline-triage"
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
	result := &PipelineResult{
		PhaseTimings: make(map[PipelinePhase]time.Duration),
	}

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
		result.PhaseTimings[phase] = time.Since(phaseStart)
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
// Uses RunSourceAnalysisParallel for parallel sub-agent execution when focused
// templates exist, falling back to monolithic analysis otherwise.
func (p *PipelineRunner) runSourceAnalysis(ctx context.Context, cfg PipelineConfig) (*SourceAnalysisResult, error) {
	saCfg := SourceAnalysisConfig{
		AgentName:    cfg.AgentName,
		AgentACPCmd:  cfg.AgentACPCmd,
		TargetURL:    cfg.TargetURL,
		SourcePath:   cfg.SourcePath,
		Files:        cfg.Files,
		Instruction:  cfg.Instruction,
		DryRun:       cfg.DryRun,
		ShowPrompt:   cfg.ShowPrompt,
		ScanUUID:     cfg.ScanUUID,
		ProjectUUID:  cfg.ProjectUUID,
		StreamWriter: cfg.StreamWriter,
	}

	saResult, _, _, err := p.engine.RunSourceAnalysisParallel(ctx, saCfg)
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
	if cfg.DryRun {
		return nil
	}
	if cfg.DiscoverFunc == nil {
		return fmt.Errorf("no discover function configured")
	}
	return cfg.DiscoverFunc(ctx)
}

// baseAgentOpts builds common Options fields from a PipelineConfig for agent calls.
func baseAgentOpts(cfg PipelineConfig, template string) Options {
	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: template,
		TargetURL:      cfg.TargetURL,
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		Instruction:    cfg.Instruction,
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
	opts := baseAgentOpts(cfg, PipelinePromptPlan)
	if cfg.Focus != "" {
		opts.Append = fmt.Sprintf("## Focus Area\n\n%s", cfg.Focus)
	}

	result, err := p.engine.Run(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("plan agent failed: %w", err)
	}

	if cfg.DryRun {
		_, _ = fmt.Fprint(os.Stdout, result.RawOutput)
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

// runScan executes phase 3: audit with plan-selected modules.
func (p *PipelineRunner) runScan(ctx context.Context, cfg PipelineConfig, plan *AttackPlan) error {
	if cfg.DryRun {
		return nil
	}
	if cfg.ScanFunc == nil {
		return fmt.Errorf("no scan function configured")
	}

	req := ScanRequest{}
	if plan != nil {
		req.ModuleTags = plan.ModuleTags
		req.ModuleIDs = plan.ModuleIDs
	}

	return cfg.ScanFunc(ctx, req)
}

// runTriageLoop runs the triage phase and optional rescan loop (phases 4-5).
// Delegates to the shared RunTriageLoop controller.
func (p *PipelineRunner) runTriageLoop(ctx context.Context, cfg PipelineConfig, result *PipelineResult) error {
	triageCfg := TriageLoopConfig{
		Engine:         p.engine,
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: PipelinePromptTriage,
		TargetURL:      cfg.TargetURL,
		Hostname:       hostnameFromURL(cfg.TargetURL),
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		Instruction:    cfg.Instruction,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		StreamWriter:   cfg.StreamWriter,
		MaxRounds:      cfg.MaxRescanRounds,
		ScanFunc:       cfg.ScanFunc,
	}

	loopResult, err := RunTriageLoop(ctx, triageCfg)
	if err != nil {
		return err
	}

	result.TriageResults = loopResult.TriageResults
	result.Confirmed += loopResult.Confirmed
	result.FalsePositives += loopResult.FalsePositives
	result.RescanRounds = loopResult.RescanRounds
	return nil
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
