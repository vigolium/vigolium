package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// pipeline command flags
var (
	pipelineTarget          string
	pipelineAgent           string
	pipelineRepo            string
	pipelineFiles           []string
	pipelineFocus           string
	pipelineTimeout         time.Duration
	pipelineDryRun          bool
	pipelineMaxRescanRounds int
	pipelineSkipPhases      []string
	pipelineStartFrom       string
	pipelineProfile         string
)

var agentPipelineCmd = &cobra.Command{
	Use:   "pipeline",
	Short: "Multi-phase AI-guided vulnerability scanning pipeline",
	Long: `Run a fixed multi-phase scanning pipeline with AI agent checkpoints.

Phases:
  1. Discover  — Content discovery and spidering (native, no AI)
  2. Plan      — AI agent analyzes discovery results, plans attack strategy
  3. Scan      — Dynamic assessment with agent-selected modules (native)
  4. Triage    — AI agent reviews findings, identifies false positives
  5. Rescan    — Targeted re-scanning based on triage recommendations
  6. Report    — Structured output from scan results

The AI agent is only called at phases 2 and 4, keeping costs low while
leveraging AI for strategic decisions.`,
	RunE: runAgentPipeline,
}

func init() {
	agentCmd.AddCommand(agentPipelineCmd)
	f := agentPipelineCmd.Flags()

	f.StringVarP(&pipelineTarget, "target", "t", "", "Target URL (required)")
	f.StringVar(&pipelineAgent, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&pipelineRepo, "repo", "", "Path to source code repository for agent context")
	f.StringSliceVar(&pipelineFiles, "files", nil, "Specific source files to include (relative to --repo)")
	f.StringVar(&pipelineFocus, "focus", "", "Focus area hint for the planning agent (e.g. 'API injection', 'auth bypass')")
	f.DurationVar(&pipelineTimeout, "timeout", 1*time.Hour, "Overall timeout for the pipeline")
	f.BoolVar(&pipelineDryRun, "dry-run", false, "Render agent prompts without executing (shows plan and triage prompts)")
	f.IntVar(&pipelineMaxRescanRounds, "max-rescan-rounds", 2, "Maximum number of triage→rescan iterations")
	f.StringSliceVar(&pipelineSkipPhases, "skip-phase", nil, "Skip specific phases (discover, plan, scan, triage, rescan, report)")
	f.StringVar(&pipelineStartFrom, "start-from", "", "Resume pipeline from a specific phase")
	f.StringVar(&pipelineProfile, "profile", "", "Scanning profile to use for scan phases")
	_ = agentPipelineCmd.MarkFlagRequired("target")
}

func runAgentPipeline(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Override SQLite path if --db flag is set
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	// Apply scanning profile if specified
	if pipelineProfile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(pipelineProfile)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return fmt.Errorf("failed to load scanning profile %q: %w", pipelineProfile, profileErr)
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return fmt.Errorf("failed to apply scanning profile %q: %w", pipelineProfile, err)
		}
	}

	// Open DB
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	repo := database.NewRepository(db)

	// Create agent engine
	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	// Build skip phases map
	skipPhases := make(map[agent.PipelinePhase]bool)
	for _, p := range pipelineSkipPhases {
		phase := agent.PipelinePhase(strings.TrimSpace(p))
		skipPhases[phase] = true
	}

	// Build pipeline config
	cfg := agent.PipelineConfig{
		TargetURL:       pipelineTarget,
		AgentName:       pipelineAgent,
		Focus:           pipelineFocus,
		RepoPath:        pipelineRepo,
		Files:           pipelineFiles,
		MaxRescanRounds: pipelineMaxRescanRounds,
		SkipPhases:      skipPhases,
		StartFrom:       agent.PipelinePhase(pipelineStartFrom),
		DryRun:          pipelineDryRun,
		ProjectUUID:     resolveProjectUUID(),
		ScanUUID:        globalScanID,
	}

	if settings.Agent.StreamEnabled() {
		cfg.StreamWriter = os.Stdout
	}

	// Wire up native scan callbacks
	cfg.DiscoverFunc = buildDiscoverFunc(settings, repo)
	cfg.ScanFunc = buildScanFunc(settings, repo)

	// Set up timeout
	if pipelineTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, pipelineTimeout)
		defer cancel()
	}

	// Print banner
	fmt.Fprintf(os.Stderr, "%s Starting pipeline scan against %s\n",
		terminal.InfoSymbol(), terminal.Cyan(pipelineTarget))
	if pipelineFocus != "" {
		fmt.Fprintf(os.Stderr, "%s Focus: %s\n",
			terminal.InfoSymbol(), pipelineFocus)
	}

	// Run pipeline
	pipelineRunner := agent.NewPipelineRunner(engine, repo)
	result, err := pipelineRunner.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("pipeline failed: %w", err)
	}

	// Print results
	printPipelineResult(result)
	return nil
}

// runPipelinePhaseRunner creates a runner with the given options, executes it, and cleans up.
func runPipelinePhaseRunner(opts *types.Options, settings *config.Settings, repo *database.Repository) error {
	scanRunner, err := runner.New(opts)
	if err != nil {
		return err
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)
	return scanRunner.RunEnumeration()
}

// pipelineBaseOpts returns default options pre-filled with common pipeline fields.
func pipelineBaseOpts() *types.Options {
	opts := types.DefaultOptions()
	opts.Targets = []string{pipelineTarget}
	opts.ScanUUID = globalScanID
	opts.ProjectUUID = resolveProjectUUID()
	opts.ConfigPath = globalConfig
	opts.Silent = true
	opts.ScanConfigPrinted = true
	return opts
}

// buildDiscoverFunc creates a callback that runs discovery + spidering using the native runner.
func buildDiscoverFunc(settings *config.Settings, repo *database.Repository) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := pipelineBaseOpts()
		opts.OnlyPhase = "discovery"
		opts.DiscoverEnabled = true
		opts.SpideringEnabled = true
		opts.HeuristicsCheck = "basic"

		fmt.Fprintf(os.Stderr, "\n%s Phase 1: Discovery & Spidering\n",
			terminal.Aqua(terminal.SymbolSparkle))

		return runPipelinePhaseRunner(opts, settings, repo)
	}
}

// buildScanFunc creates a callback that runs dynamic assessment with specified module filters.
func buildScanFunc(settings *config.Settings, repo *database.Repository) func(ctx context.Context, moduleTags []string, moduleIDs []string) error {
	return func(ctx context.Context, moduleTags []string, moduleIDs []string) error {
		opts := pipelineBaseOpts()
		opts.OnlyPhase = "dynamic-assessment"
		opts.SkipIngestion = true
		opts.HeuristicsCheck = "none"
		opts.Modules = resolveModulesFromPlan(moduleTags, moduleIDs)
		opts.PassiveModules = []string{"all"}

		fmt.Fprintf(os.Stderr, "\n%s Scanning with modules: %s\n",
			terminal.Aqua(terminal.SymbolSparkle),
			summarizeModules(opts.Modules))

		return runPipelinePhaseRunner(opts, settings, repo)
	}
}

// resolveModulesFromPlan converts agent-suggested tags and IDs into module ID list.
func resolveModulesFromPlan(tags []string, ids []string) []string {
	moduleSet := make(map[string]bool)

	// Resolve tags to module IDs
	if len(tags) > 0 {
		resolved := modules.ResolveModuleTags(tags)
		for _, id := range resolved {
			moduleSet[id] = true
		}
	}

	// Add explicit module IDs
	for _, id := range ids {
		moduleSet[id] = true
	}

	if len(moduleSet) == 0 {
		return []string{"all"}
	}

	result := make([]string, 0, len(moduleSet))
	for id := range moduleSet {
		result = append(result, id)
	}
	return result
}

// summarizeModules returns a human-readable summary of selected modules.
func summarizeModules(mods []string) string {
	if len(mods) == 1 && mods[0] == "all" {
		return "all modules"
	}
	if len(mods) <= 5 {
		return strings.Join(mods, ", ")
	}
	return fmt.Sprintf("%d modules", len(mods))
}

// printPipelineResult prints a summary of the pipeline execution.
func printPipelineResult(result *agent.PipelineResult) {
	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Pipeline completed"))

	fmt.Fprintf(os.Stderr, "  Duration:        %s\n", result.Duration.Round(time.Second))
	fmt.Fprintf(os.Stderr, "  Phases run:      %s\n", formatPhases(result.PhasesRun))
	fmt.Fprintf(os.Stderr, "  Total findings:  %d\n", result.TotalFindings)

	if len(result.TriageResults) > 0 {
		fmt.Fprintf(os.Stderr, "  Confirmed:       %d\n", result.Confirmed)
		fmt.Fprintf(os.Stderr, "  False positives: %d\n", result.FalsePositives)
		fmt.Fprintf(os.Stderr, "  Rescan rounds:   %d\n", result.RescanRounds)
	}

	if result.Plan != nil {
		fmt.Fprintf(os.Stderr, "\n  %s Attack Plan:\n", terminal.InfoSymbol())
		if len(result.Plan.ModuleTags) > 0 {
			fmt.Fprintf(os.Stderr, "    Module tags:   %s\n", strings.Join(result.Plan.ModuleTags, ", "))
		}
		if len(result.Plan.FocusAreas) > 0 {
			fmt.Fprintf(os.Stderr, "    Focus areas:   %s\n", strings.Join(result.Plan.FocusAreas, ", "))
		}
		if result.Plan.Notes != "" {
			fmt.Fprintf(os.Stderr, "    Notes:         %s\n", result.Plan.Notes)
		}
	}
}

// formatPhases returns a comma-separated list of phase names.
func formatPhases(phases []agent.PipelinePhase) string {
	names := make([]string, len(phases))
	for i, p := range phases {
		names[i] = string(p)
	}
	return strings.Join(names, " → ")
}
