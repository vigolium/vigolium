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
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// agent swarm command flags
var (
	swarmTarget             string
	swarmInput              string
	swarmRecordUUID         string
	swarmSource             string
	swarmFiles              []string
	swarmVulnType           string
	swarmModules            []string
	swarmMaxIterations      int
	swarmAgentName          string
	swarmAgentACPCmd        string
	swarmDryRun             bool
	swarmShowPrompt         bool
	swarmSourceAnalysisOnly bool
	swarmTimeout            time.Duration
	swarmProfile            string
	swarmOnlyPhase          string
	swarmSkipPhases         []string
	swarmInstruction        string
	swarmInstructionFile    string
	swarmDiscover           bool
	swarmBatchConcurrency   int
	swarmMaxMasterRetries   int
)

var agentSwarmCmd = &cobra.Command{
	Use:   "swarm",
	Short: "Agentic scan: AI-guided targeted vulnerability swarm",
	Long: `Run an agentic scan swarm against a specific input.

The master agent analyzes the target, selects appropriate scanner modules,
generates custom attack payloads as JavaScript extensions, executes the scan,
and triages the results.

Supported input types (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)
  - Record UUID: abc123-... (from http_records table)

When input is piped via stdin, it is automatically read (no --input needed).`,
	RunE: runAgentSwarm,
}

func init() {
	agentCmd.AddCommand(agentSwarmCmd)
	f := agentSwarmCmd.Flags()

	f.StringVarP(&swarmTarget, "target", "t", "", "Target URL (required when --source is used)")
	f.StringVar(&swarmInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&swarmRecordUUID, "record-uuid", "", "HTTP record UUID from database")
	f.StringVar(&swarmSource, "source", "", "Path to application source code for route discovery")
	f.StringSliceVar(&swarmFiles, "files", nil, "Specific source files to include (relative to --source)")
	f.StringVar(&swarmVulnType, "vuln-type", "", "Vulnerability type focus (e.g. sqli, xss, ssrf)")
	f.StringSliceVarP(&swarmModules, "modules", "m", nil, "Explicit module names to include")
	f.IntVar(&swarmMaxIterations, "max-iterations", 3, "Maximum triage-rescan iterations")
	f.StringVar(&swarmAgentName, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&swarmAgentACPCmd, "agent-acp-cmd", "", "Custom ACP agent command (e.g. 'traecli acp'), overrides --agent")
	f.BoolVar(&swarmDryRun, "dry-run", false, "Render prompts without executing")
	f.BoolVar(&swarmShowPrompt, "show-prompt", false, "Print rendered prompts to stderr before executing")
	f.BoolVar(&swarmSourceAnalysisOnly, "source-analysis-only", false, "Run only the source analysis phase and exit")
	f.DurationVar(&swarmTimeout, "timeout", 15*time.Minute, "Maximum swarm duration")
	f.StringVar(&swarmProfile, "profile", "", "Scanning profile to use")
	f.StringVar(&swarmOnlyPhase, "only", "", "Run only this scanning phase (discovery, spidering, spa, audit, external-harvest)")
	f.StringSliceVar(&swarmSkipPhases, "skip", nil, "Skip specific phases (discovery, spidering, spa, audit, external-harvest)")
	f.StringVar(&swarmInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompts)")
	f.StringVar(&swarmInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.BoolVar(&swarmDiscover, "discover", false, "Run discovery+spidering before master agent planning to expand attack surface")
	f.IntVar(&swarmBatchConcurrency, "batch-concurrency", 0, "Max parallel master agent batches (0 = auto, scales with CPU count)")
	f.IntVar(&swarmMaxMasterRetries, "max-master-retries", 3, "Max master agent retries on parse failure")
}

func runAgentSwarm(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Validate: at least one input source (stdin is checked later in buildSwarmInputs)
	if swarmTarget == "" && swarmInput == "" && swarmRecordUUID == "" && swarmSource == "" && !stdinIsPiped() {
		return fmt.Errorf("at least one input is required: --target, --input, --record-uuid, --source, or pipe via stdin")
	}

	// --source requires --target for hostname mapping
	if swarmSource != "" && swarmTarget == "" && swarmInput == "" && swarmRecordUUID == "" && !stdinIsPiped() {
		return fmt.Errorf("--target is required when using --source (used to filter discovered routes by hostname)")
	}

	// --source-analysis-only requires --source
	if swarmSourceAnalysisOnly && swarmSource == "" {
		return fmt.Errorf("--source-analysis-only requires --source")
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

	// Apply scanning profile
	if swarmProfile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(swarmProfile)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return fmt.Errorf("failed to load scanning profile %q: %w", swarmProfile, profileErr)
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return fmt.Errorf("failed to apply scanning profile %q: %w", swarmProfile, err)
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

	// Create agent engine with warm sessions for subprocess reuse across swarm phases
	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	// Resolve project UUID
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	instruction, instrErr := resolveInstruction(swarmInstruction, swarmInstructionFile)
	if instrErr != nil {
		return instrErr
	}

	// Build inputs list
	inputs, err := buildSwarmInputs()
	if err != nil {
		return err
	}

	// Create session directory upfront so callbacks can write to it
	swarmRunID := "agt-" + uuid.New().String()
	sessionDir, sdErr := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), swarmRunID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}

	// Track generated auth config path (set by SourceAnalysisCallback, used by scan callbacks)
	var generatedAuthConfig string

	// Build swarm config
	cfg := agent.SwarmConfig{
		Inputs:             inputs,
		Instruction:        instruction,
		SourcePath:         swarmSource,
		Files:              swarmFiles,
		VulnType:           swarmVulnType,
		ModuleNames:        swarmModules,
		OnlyPhase:          swarmOnlyPhase,
		SkipPhases:         swarmSkipPhases,
		MaxIterations:      swarmMaxIterations,
		BatchConcurrency:   swarmBatchConcurrency,
		MaxMasterRetries:   swarmMaxMasterRetries,
		AgentName:          swarmAgentName,
		AgentACPCmd:        swarmAgentACPCmd,
		DryRun:             swarmDryRun,
		ShowPrompt:         swarmShowPrompt,
		SourceAnalysisOnly: swarmSourceAnalysisOnly,
		SessionsDir:        settings.Agent.EffectiveSessionsDir(),
		SessionDir:         sessionDir,
		ProjectUUID:        projectUUID,
		ScanUUID:           globalScanID,
	}

	if settings.Agent.StreamEnabled() {
		cfg.StreamWriter = os.Stdout
	}

	// Wire source analysis callback to process session config into auth-config.yaml
	cfg.SourceAnalysisCallback = func(saResult *agent.SourceAnalysisResult) error {
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

	// Wire scan callback with auth config support
	cfg.ScanFunc = buildAgentSwarmScanFunc(settings, repo, swarmOnlyPhase, swarmSkipPhases, &generatedAuthConfig)

	// Wire optional discovery callback
	if swarmDiscover {
		cfg.DiscoverFunc = buildSwarmDiscoverFunc(settings, repo, &generatedAuthConfig)
	}

	// Wire SAST callback automatically when --source is provided
	if swarmSource != "" {
		cfg.SASTFunc = buildSwarmSASTFunc(settings, repo, swarmSource, &generatedAuthConfig)
	}

	// Set up timeout
	if swarmTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, swarmTimeout)
		defer cancel()
	}

	// Resolve effective agent name for display
	effectiveAgent := cfg.AgentName
	if cfg.AgentACPCmd != "" {
		effectiveAgent = cfg.AgentACPCmd
	} else if effectiveAgent == "" {
		effectiveAgent = settings.Agent.DefaultAgent
	}

	// Print banner
	inputDesc := swarmTarget
	if inputDesc == "" && swarmInput != "" {
		inputDesc = truncateSwarmInput(swarmInput, 80)
	}
	if inputDesc == "" && swarmRecordUUID != "" {
		inputDesc = "record:" + swarmRecordUUID
	}
	promptPath := agent.ResolveTemplatePath(agent.SwarmPromptMaster, settings.Agent.TemplatesDir)
	fmt.Fprintf(os.Stderr, "%s Starting agentic scan (swarm): %s\n",
		terminal.InfoSymbol(), terminal.GrbGreen(inputDesc))
	fmt.Fprintf(os.Stderr, "%s Agent: %s\n",
		terminal.InfoSymbol(), terminal.GrbGreen(effectiveAgent))
	fmt.Fprintf(os.Stderr, "%s Prompt: %s %s\n",
		terminal.InfoSymbol(), terminal.Orange(agent.SwarmPromptMaster), terminal.Muted(promptPath))
	if swarmSource != "" {
		fmt.Fprintf(os.Stderr, "%s Source code: %s\n",
			terminal.InfoSymbol(), terminal.GrbGreen(terminal.ShortenHome(swarmSource)))
	}
	if swarmVulnType != "" {
		fmt.Fprintf(os.Stderr, "%s Vulnerability focus: %s\n",
			terminal.InfoSymbol(), terminal.GrbRed(swarmVulnType))
	}
	if swarmDiscover {
		fmt.Fprintf(os.Stderr, "%s Discovery: %s\n",
			terminal.InfoSymbol(), terminal.GrbGreen("enabled (crawling + spidering before planning)"))
	}
	if swarmSource != "" {
		sastTools := "ast-grep route extraction + secret detection"
		if settings.SourceAware.ThirdPartyIntegration.Enabled {
			var tools []string
			for name, tool := range settings.SourceAware.ThirdPartyIntegration.Tools {
				if tool.Enabled {
					tools = append(tools, name)
				}
			}
			if len(tools) > 0 {
				sastTools += " + " + strings.Join(tools, ", ")
			}
		}
		fmt.Fprintf(os.Stderr, "%s SAST: %s\n",
			terminal.InfoSymbol(), terminal.GrbGreen("enabled ("+sastTools+")"))
	}

	// Wire phase callback for verbose output
	cfg.PhaseCallback = func(phase string) {
		desc := agent.SwarmPhaseDescription(phase)
		if desc != "" {
			fmt.Fprintf(os.Stderr, "\n%s Phase [%s] - %s\n",
				terminal.InfoSymbol(), terminal.BoldOrange(phase), terminal.Muted(desc))
		} else {
			fmt.Fprintf(os.Stderr, "\n%s Phase [%s]\n",
				terminal.InfoSymbol(), terminal.BoldOrange(phase))
		}
		promptName := agent.SwarmPhasePrompt(phase)
		if promptName != "" {
			pp := agent.ResolveTemplatePath(promptName, settings.Agent.TemplatesDir)
			fmt.Fprintf(os.Stderr, "  %s Phase configuration: prompt: %s %s\n\n",
				terminal.FunctionSymbol(), terminal.Orange(promptName), terminal.Muted(pp))
		}
	}

	// Run swarm
	swarmRunner := agent.NewSwarmRunner(engine, repo)
	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("agent swarm failed: %w", err)
	}

	printSwarmResult(result)
	return nil
}

func buildSwarmInputs() ([]string, error) {
	var inputs []string

	if swarmTarget != "" {
		inputs = append(inputs, swarmTarget)
	}

	if swarmInput != "" {
		if swarmInput == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("failed to read from stdin: %w", err)
			}
			inputs = append(inputs, string(data))
		} else {
			inputs = append(inputs, swarmInput)
		}
	}

	if swarmRecordUUID != "" {
		inputs = append(inputs, swarmRecordUUID)
	}

	// Auto-detect stdin when no explicit input is provided
	if len(inputs) == 0 {
		if data, ok := readStdinIfPiped(); ok {
			inputs = append(inputs, data)
		}
	}

	return inputs, nil
}

// buildAgentSwarmScanFunc creates a callback that runs the scan.
// When IsRescan=false, it runs a full scan (all phases, all modules) by default.
// When IsRescan=true, it restricts to audit with targeted modules.
// The onlyPhase and skipPhases parameters allow user control via --only/--skip flags.
// authConfigPath points to a generated auth-config.yaml from source analysis (may be empty).
func buildAgentSwarmScanFunc(settings *config.Settings, repo *database.Repository, onlyPhase string, skipPhases []string, authConfigPath *string) agent.ScanFunc {
	return func(ctx context.Context, req agent.ScanRequest) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{swarmTarget}
		opts.ScanUUID = globalScanID
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		opts.ProjectUUID = projectUUID
		opts.ConfigPath = globalConfig
		opts.HeuristicsCheck = "none"
		opts.PassiveModules = []string{"all"}

		// Apply generated auth config from source analysis or custom instruction
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
		}

		if req.IsRescan {
			// Triage rescans: targeted audit only
			opts.OnlyPhase = "audit"
			opts.SkipIngestion = true
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
		} else {
			// Initial scan: full scan with all modules
			opts.Modules = []string{"all"}
			// Apply user-specified phase control
			if onlyPhase != "" {
				opts.OnlyPhase = onlyPhase
			}
			if len(skipPhases) > 0 {
				opts.SkipPhases = skipPhases
			}
		}

		// Pass through verbose flag so audit traffic/finding lines are printed
		opts.Verbose = globalVerbose

		// Clone settings to avoid mutating shared config
		settingsCopy := *settings
		if req.ExtensionDir != "" {
			settingsCopy.Audit.Extensions.Enabled = true
			settingsCopy.Audit.Extensions.CustomDir = append(
				settingsCopy.Audit.Extensions.CustomDir,
				filepath.Join(req.ExtensionDir, "*.js"),
			)
		}

		fmt.Fprintf(os.Stderr, "%s Scanning with modules: %s\n",
			terminal.GrbRed(terminal.SymbolSparkle),
			summarizeModules(opts.Modules))

		scanRunner, runErr := runner.New(opts)
		if runErr != nil {
			return runErr
		}
		defer scanRunner.Close()

		scanRunner.SetSettings(&settingsCopy)
		scanRunner.SetRepository(repo)
		return scanRunner.RunNativeScan()
	}
}

// buildSwarmDiscoverFunc creates a callback that runs discovery + spidering
// before the master agent planning phase. This expands the attack surface
// by crawling/spidering the target and populating the database with HTTP records.
func buildSwarmDiscoverFunc(settings *config.Settings, repo *database.Repository, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{swarmTarget}
		opts.ScanUUID = globalScanID
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		opts.ProjectUUID = projectUUID
		opts.ConfigPath = globalConfig
		opts.OnlyPhase = "discovery"
		opts.DiscoverEnabled = true
		opts.SpideringEnabled = true
		opts.HeuristicsCheck = "basic"
		opts.Silent = true
		opts.ScanConfigPrinted = true

		// Apply generated auth config for authenticated crawling
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
		}

		fmt.Fprintf(os.Stderr, "%s Discovery & Spidering (expanding attack surface)\n",
			terminal.Aqua(terminal.SymbolSparkle))

		return runPipelinePhaseRunner(opts, settings, repo)
	}
}

func printSwarmResult(result *agent.SwarmResult) {
	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Agentic scan (swarm) completed"))

	fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Duration:"), result.Duration.Round(time.Second))
	fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Agent run:"), terminal.Gray(result.AgentRunUUID))
	if result.SessionID != "" {
		fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Session ID:"), terminal.Gray(result.SessionID))
	}
	if result.SessionDir != "" {
		fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Session dir:"), terminal.Gray(terminal.ShortenHome(result.SessionDir)))
	}

	// Records summary
	if result.TotalRecords > 0 {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.Aqua(terminal.SymbolInfo),
			terminal.BoldAqua("Records:"),
			fmt.Sprintf("%s http records ingested", terminal.BoldCyan(fmt.Sprintf("%d", result.TotalRecords))))
	}

	// Findings summary with severity breakdown
	fmt.Fprintf(os.Stderr, "  %s %s %s",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Findings:"),
		fmt.Sprintf("%s issues found", colorFindingCount(result.TotalFindings)))
	if len(result.SeverityCounts) > 0 && result.TotalFindings > 0 {
		fmt.Fprintf(os.Stderr, " — %s", formatSeverityWithSymbols(result.SeverityCounts))
	}
	fmt.Fprintln(os.Stderr)

	if result.SwarmPlan != nil {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Swarm Plan:"))
		if len(result.SwarmPlan.ModuleTags) > 0 {
			coloredTags := make([]string, len(result.SwarmPlan.ModuleTags))
			for i, tag := range result.SwarmPlan.ModuleTags {
				coloredTags[i] = terminal.Cyan(tag)
			}
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Module tags:"), strings.Join(coloredTags, terminal.Gray(", ")))
		}
		if len(result.SwarmPlan.Extensions) > 0 {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Extensions:"), terminal.BoldYellow(fmt.Sprintf("%d generated", len(result.SwarmPlan.Extensions))))
			for _, ext := range result.SwarmPlan.Extensions {
				fmt.Fprintf(os.Stderr, "      %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(ext.Filename+":"), ext.Reason)
			}
		}
		if len(result.SwarmPlan.FocusAreas) > 0 {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Focus areas:"), terminal.Orange(fmt.Sprintf("%d", len(result.SwarmPlan.FocusAreas))))
			for _, area := range result.SwarmPlan.FocusAreas {
				title, detail := splitFocusArea(area)
				if detail != "" {
					fmt.Fprintf(os.Stderr, "      %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(title+":"), terminal.Muted(detail))
				} else {
					fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.BoldCyan(area))
				}
			}
		}
		if result.SwarmPlan.Notes != "" {
			fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray("Notes:"))
			for _, line := range strings.Split(result.SwarmPlan.Notes, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				line = strings.TrimPrefix(line, "- ")
				fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.Muted(line))
			}
		}
	}

	if len(result.TriageResults) > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Triage:"))
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Confirmed:"), terminal.BoldGreen(fmt.Sprintf("%d", result.Confirmed)))
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("False positives:"), terminal.Gray(fmt.Sprintf("%d", result.FalsePositives)))
		fmt.Fprintf(os.Stderr, "    %-17s %d\n", terminal.Gray("Iterations:"), result.Iterations)
	}

}

// colorFindingCount returns a colored finding count based on severity.
func colorFindingCount(count int) string {
	s := fmt.Sprintf("%d", count)
	if count == 0 {
		return terminal.Green(s)
	}
	return terminal.BoldYellow(s)
}

// formatSeverityWithSymbols formats severity counts with colored symbols.
// Example: ❖ 2 high, ◆ 2 medium, • 4 low, ? 1 suspect, ◇ 2 info
func formatSeverityWithSymbols(counts map[string]int) string {
	type sevEntry struct {
		symbol string
		count  int
		label  string
	}
	entries := []sevEntry{
		{terminal.CriticalSymbol(), counts["critical"], "critical"},
		{terminal.HighSymbol(), counts["high"], "high"},
		{terminal.MediumSymbol(), counts["medium"], "medium"},
		{terminal.LowSymbol(), counts["low"], "low"},
		{terminal.SuspectSymbol(), counts["suspect"], "suspect"},
		{terminal.InfoSeveritySymbol(), counts["info"], "info"},
	}

	var parts []string
	for _, e := range entries {
		if e.count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d %s", e.symbol, e.count, e.label))
		}
	}
	return strings.Join(parts, ", ")
}

// splitFocusArea splits a focus area string like "**Title**: description" into title and detail.
// It strips markdown bold markers from the title.
func splitFocusArea(area string) (string, string) {
	// Try "**Title**: detail" or "**Title** — detail"
	for _, sep := range []string{"**: ", "** — ", "** - "} {
		if idx := strings.Index(area, sep); idx > 0 {
			title := strings.TrimPrefix(area[:idx], "**")
			title = strings.TrimSuffix(title, "**")
			detail := area[idx+len(sep):]
			return strings.TrimSpace(title), strings.TrimSpace(detail)
		}
	}
	// Try "Title: detail" (no markdown)
	if idx := strings.Index(area, ": "); idx > 0 && idx < 60 {
		return area[:idx], area[idx+2:]
	}
	return area, ""
}

// buildSwarmSASTFunc creates a callback that runs the native SAST phase
// (ast-grep route extraction, Kingfisher secret detection, third-party tools).
// This is automatically wired when --source is provided.
func buildSwarmSASTFunc(settings *config.Settings, repo *database.Repository, sourcePath string, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{swarmTarget}
		opts.ScanUUID = globalScanID
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		opts.ProjectUUID = projectUUID
		opts.ConfigPath = globalConfig
		opts.SourcePath = sourcePath
		opts.SASTEnabled = true
		opts.OnlyPhase = "sast"
		// Resolve OnlyPhase into concrete phase flags — the runner's RunNativeScan
		// does NOT resolve OnlyPhase itself; that only happens in scan.go's CLI handler.
		// Without these, the runner would also run discovery + audit after SAST.
		opts.SkipIngestion = true
		opts.SkipAudit = true
		opts.HeuristicsCheck = "none"
		opts.Silent = true
		opts.ScanConfigPrinted = true

		// Apply generated auth config if available
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
		}

		fmt.Fprintf(os.Stderr, "%s SAST analysis (ast-grep + secret detection + third-party tools)\n",
			terminal.GrbRed(terminal.SymbolSparkle))

		return runPipelinePhaseRunner(opts, settings, repo)
	}
}

func truncateSwarmInput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
