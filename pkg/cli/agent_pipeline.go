package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// pipeline command flags
var (
	pipelineTarget          string
	pipelineInput           string
	pipelineAgent           string
	pipelineSource          string
	pipelineFiles           []string
	pipelineFocus           string
	pipelineTimeout         time.Duration
	pipelineACPCmd          string
	pipelineDryRun          bool
	pipelineShowPrompt      bool
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
  0. Source Analysis — AI agent analyzes source code (when --source provided)
  1. Discover        — Content discovery and spidering (native, no AI)
  2. Plan            — AI agent analyzes discovery results, plans attack strategy
  3. Scan            — Dynamic assessment with agent-selected modules (native)
  4. Triage          — AI agent reviews findings, identifies false positives
  5. Rescan          — Targeted re-scanning based on triage recommendations
  6. Report          — Structured output from scan results

The AI agent is only called at phases 0, 2, and 4, keeping costs low while
leveraging AI for strategic decisions. Phase 0 extracts routes, session
configuration, and custom scanner extensions from source code.

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)

When input is piped via stdin, it is automatically read (no --input needed).
The target URL is extracted from the input when --target is not provided.`,
	RunE: runAgentPipeline,
}

func init() {
	agentCmd.AddCommand(agentPipelineCmd)
	f := agentPipelineCmd.Flags()

	f.StringVarP(&pipelineTarget, "target", "t", "", "Target URL (derived from --input if not set)")
	f.StringVar(&pipelineInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&pipelineAgent, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&pipelineACPCmd, "agent-acp-cmd", "", "Custom ACP agent command (e.g. 'traecli acp'), overrides --agent")
	f.StringVar(&pipelineSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&pipelineFiles, "files", nil, "Specific source files to include (relative to --source)")
	f.StringVar(&pipelineFocus, "focus", "", "Focus area hint for the planning agent (e.g. 'API injection', 'auth bypass')")
	f.DurationVar(&pipelineTimeout, "timeout", 1*time.Hour, "Maximum total pipeline duration")
	f.BoolVar(&pipelineDryRun, "dry-run", false, "Render agent prompts without executing (shows plan and triage prompts)")
	f.BoolVar(&pipelineShowPrompt, "show-prompt", false, "Print rendered prompts to stderr before executing")
	f.IntVar(&pipelineMaxRescanRounds, "max-rescan-rounds", 2, "Maximum number of triage->rescan iterations")
	f.StringSliceVar(&pipelineSkipPhases, "skip-phase", nil, "Skip specific phases (source-analysis, discover, plan, scan, triage, rescan, report)")
	f.StringVar(&pipelineStartFrom, "start-from", "", "Resume pipeline from a specific phase")
	f.StringVar(&pipelineProfile, "profile", "", "Scanning profile to use for scan phases")
}

func runAgentPipeline(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Resolve input: explicit --input, stdin pipe, or --input -
	inputData := pipelineInput
	if inputData == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		inputData = string(data)
	} else if inputData == "" && pipelineTarget == "" {
		if data, ok := readStdinIfPiped(); ok {
			inputData = data
		}
	}

	// Derive target from input when --target is not provided
	if pipelineTarget == "" && inputData != "" {
		ctx := context.Background()
		targetURL, err := resolveTargetFromInput(ctx, inputData, nil)
		if err != nil {
			return fmt.Errorf("could not derive target from input: %w\nUse --target to specify explicitly", err)
		}
		pipelineTarget = targetURL
	}

	if pipelineTarget == "" {
		return fmt.Errorf("target is required: use --target, --input, or pipe via stdin")
	}

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

	pipelineProjectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	// Create session directory for pipeline artifacts
	pipelineRunID := "agt-" + uuid.New().String()
	sessionDir, sdErr := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), pipelineRunID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}

	// Track generated auth config path (set by SourceAnalysisCallback, used by scan callbacks)
	var generatedAuthConfig string

	// Build pipeline config
	cfg := agent.PipelineConfig{
		TargetURL:       pipelineTarget,
		AgentName:       pipelineAgent,
		AgentACPCmd:     pipelineACPCmd,
		Focus:           pipelineFocus,
		SourcePath:      pipelineSource,
		Files:           pipelineFiles,
		MaxRescanRounds: pipelineMaxRescanRounds,
		SkipPhases:      skipPhases,
		StartFrom:       agent.PipelinePhase(pipelineStartFrom),
		DryRun:          pipelineDryRun,
		ShowPrompt:      pipelineShowPrompt,
		ProjectUUID:     pipelineProjectUUID,
		ScanUUID:        globalScanID,
	}

	// Wire source analysis callback to process generated extensions and session config
	cfg.SourceAnalysisCallback = func(saResult *agent.SourceAnalysisResult) error {
		// Write generated extensions to session directory
		if len(saResult.Extensions) > 0 {
			dir, writeErr := agent.WriteExtensionsToSessionDir(saResult.Extensions, sessionDir)
			if writeErr != nil {
				return fmt.Errorf("failed to write generated extensions: %w", writeErr)
			}
			settings.DynamicAssessment.Extensions.Enabled = true
			settings.DynamicAssessment.Extensions.CustomDir = append(settings.DynamicAssessment.Extensions.CustomDir, filepath.Join(dir, "*.js"))
		}

		// Write session config to session directory
		if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
			yamlData, marshalErr := yaml.Marshal(convertSessionConfig(saResult.SessionConfig))
			if marshalErr != nil {
				return fmt.Errorf("failed to marshal session config: %w", marshalErr)
			}
			authPath := filepath.Join(sessionDir, "auth-config.yaml")
			if writeErr := os.WriteFile(authPath, yamlData, 0644); writeErr != nil {
				return fmt.Errorf("failed to write auth config: %w", writeErr)
			}
			generatedAuthConfig = authPath
			zap.L().Info("Generated auth config written",
				zap.String("path", authPath),
				zap.Int("sessions", len(saResult.SessionConfig.Sessions)))
		}
		return nil
	}

	if settings.Agent.StreamEnabled() {
		cfg.StreamWriter = os.Stdout
	}

	// Wire up native scan callbacks.
	// Pass &generatedAuthConfig so closures see the value set by SourceAnalysisCallback.
	cfg.DiscoverFunc = buildDiscoverFunc(settings, repo, &generatedAuthConfig)
	cfg.ScanFunc = buildScanFunc(settings, repo, &generatedAuthConfig)

	// Set up timeout
	if pipelineTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, pipelineTimeout)
		defer cancel()
	}

	// Print banner
	fmt.Fprintf(os.Stderr, "%s Starting pipeline scan against %s\n",
		terminal.InfoSymbol(), terminal.Cyan(pipelineTarget))
	if pipelineSource != "" {
		fmt.Fprintf(os.Stderr, "%s Source code: %s\n",
			terminal.InfoSymbol(), pipelineSource)
	}
	if pipelineFocus != "" {
		fmt.Fprintf(os.Stderr, "%s Focus: %s\n",
			terminal.InfoSymbol(), pipelineFocus)
	}

	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "%s Session: %s\n",
			terminal.InfoSymbol(), terminal.Gray(sessionDir))
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

// sessionConfigYAML is the YAML-serializable session config format
// matching pkg/session.SessionConfig.
type sessionConfigYAML struct {
	Sessions []sessionEntryYAML `yaml:"sessions"`
}

type sessionEntryYAML struct {
	Name    string            `yaml:"name"`
	Role    string            `yaml:"role"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Login   *loginFlowYAML    `yaml:"login,omitempty"`
}

type loginFlowYAML struct {
	URL         string            `yaml:"url"`
	Method      string            `yaml:"method"`
	ContentType string            `yaml:"content_type,omitempty"`
	Body        string            `yaml:"body,omitempty"`
	Extract     []extractRuleYAML `yaml:"extract"`
}

type extractRuleYAML struct {
	Source  string `yaml:"source"`
	Name    string `yaml:"name,omitempty"`
	Path    string `yaml:"path,omitempty"`
	ApplyAs string `yaml:"apply_as,omitempty"`
}

// convertSessionConfig converts agent session config to the YAML format expected by pkg/session.
func convertSessionConfig(cfg *agent.AgentSessionConfig) sessionConfigYAML {
	result := sessionConfigYAML{}
	for _, s := range cfg.Sessions {
		entry := sessionEntryYAML{
			Name:    s.Name,
			Role:    s.Role,
			Headers: s.Headers,
		}
		if s.Login != nil {
			login := &loginFlowYAML{
				URL:         s.Login.URL,
				Method:      s.Login.Method,
				ContentType: s.Login.ContentType,
				Body:        s.Login.Body,
			}
			for _, e := range s.Login.Extract {
				login.Extract = append(login.Extract, extractRuleYAML{
					Source:  e.Source,
					Name:    e.Name,
					Path:    e.Path,
					ApplyAs: e.ApplyAs,
				})
			}
			entry.Login = login
		}
		result.Sessions = append(result.Sessions, entry)
	}
	return result
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
func pipelineBaseOpts() (*types.Options, error) {
	opts := types.DefaultOptions()
	opts.Targets = []string{pipelineTarget}
	opts.ScanUUID = globalScanID
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return nil, err
	}
	opts.ProjectUUID = projectUUID
	opts.ConfigPath = globalConfig
	opts.Silent = true
	opts.ScanConfigPrinted = true
	return opts, nil
}

// buildDiscoverFunc creates a callback that runs discovery + spidering using the native runner.
func buildDiscoverFunc(settings *config.Settings, repo *database.Repository, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts, err := pipelineBaseOpts()
		if err != nil {
			return err
		}
		opts.OnlyPhase = "discovery"
		opts.DiscoverEnabled = true
		opts.SpideringEnabled = true
		opts.HeuristicsCheck = "basic"
		if *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
		}

		fmt.Fprintf(os.Stderr, "\n%s Phase 1: Discovery & Spidering\n",
			terminal.Aqua(terminal.SymbolSparkle))

		return runPipelinePhaseRunner(opts, settings, repo)
	}
}

// buildScanFunc creates a callback that runs dynamic assessment with specified module filters.
func buildScanFunc(settings *config.Settings, repo *database.Repository, authConfigPath *string) func(ctx context.Context, moduleTags []string, moduleIDs []string) error {
	return func(ctx context.Context, moduleTags []string, moduleIDs []string) error {
		opts, err := pipelineBaseOpts()
		if err != nil {
			return err
		}
		opts.OnlyPhase = "dynamic-assessment"
		opts.SkipIngestion = true
		opts.HeuristicsCheck = "none"
		opts.Modules = agent.ResolveModulesFromPlan(moduleTags, moduleIDs)
		opts.PassiveModules = []string{"all"}
		if *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
		}

		fmt.Fprintf(os.Stderr, "\n%s Scanning with modules: %s\n",
			terminal.Aqua(terminal.SymbolSparkle),
			summarizeModules(opts.Modules))

		return runPipelinePhaseRunner(opts, settings, repo)
	}
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

	if result.SourceAnalysis != nil {
		fmt.Fprintf(os.Stderr, "\n  %s Source Analysis:\n", terminal.InfoSymbol())
		fmt.Fprintf(os.Stderr, "    HTTP records:    %d\n", len(result.SourceAnalysis.HTTPRecords))
		fmt.Fprintf(os.Stderr, "    Extensions:      %d\n", len(result.SourceAnalysis.Extensions))
		if result.SourceAnalysis.SessionConfig != nil {
			fmt.Fprintf(os.Stderr, "    Session config:  %d session(s)\n", len(result.SourceAnalysis.SessionConfig.Sessions))
		}
	}

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
	return strings.Join(names, " -> ")
}
