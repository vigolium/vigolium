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
	swarmTarget              string
	swarmInput               string
	swarmRecordUUID          string
	swarmSource              string
	swarmFiles               []string
	swarmVulnType            string
	swarmFocus               string
	swarmModules             []string
	swarmMaxIterations       int
	swarmAgentName           string
	swarmDryRun              bool
	swarmShowPrompt          bool
	swarmSourceAnalysisOnly  bool
	swarmTimeout             time.Duration
	swarmProfile             string
	swarmOnlyPhase           string
	swarmSkipPhases          []string
	swarmStartFrom           string
	swarmInstruction         string
	swarmInstructionFile     string
	swarmDiscover            bool
	swarmBatchConcurrency    int
	swarmMaxMasterRetries    int
	swarmSubAgentConcurrency int
	swarmSkipSAST            bool
	swarmCodeAudit           bool
	swarmTriage              bool
	swarmMaxPlanRecords      int
	swarmMasterBatchSize     int
	swarmProbeConcurrency    int
	swarmProbeTimeout        time.Duration
	swarmMaxProbeBody        int
	swarmBrowser             bool
	swarmAuth                bool
	swarmCredentials         string
	swarmArchon          string
)

var agentSwarmCmd = &cobra.Command{
	Use:   "swarm [prompt]",
	Short: "Agentic scan: AI-guided targeted vulnerability swarm",
	Long: `Run an agentic scan swarm against a specific input.

The master agent analyzes the target, selects appropriate scanner modules,
generates custom attack payloads as JavaScript extensions, executes the scan,
and triages the results.

Supports natural language prompts as a positional argument:
  vigolium agent swarm "scan VAmPI source at ~/src/VAmPI on localhost:3005"
  vigolium agent swarm "scan all source code from ~/src/crAPI, ~/src/DVWA"

The prompt is parsed by an AI to extract target URLs, source paths, and focus areas.
Use --dry-run to preview what the parser extracts without executing.

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)
  - Record UUID: abc123-... (from http_records table)

When input is piped via stdin, it is automatically read (no --input needed).`,
	Args: cobra.MaximumNArgs(1),
	Example: `  # Swarm a single URL
  vigolium agent swarm --input "https://example.com/api/users?id=1"

  # Swarm a curl command
  vigolium agent swarm --input "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login"

  # Pipe a raw HTTP request from stdin
  cat request.txt | vigolium agent swarm

  # Swarm with source code for route discovery
  vigolium agent swarm -t https://example.com --source ./src

  # Source-aware swarm with specific files
  vigolium agent swarm -t https://example.com --source ./src --files "routes/api.js,controllers/auth.js"

  # Only run source analysis (no scanning)
  vigolium agent swarm -t https://example.com --source ./src --source-analysis-only

  # Focus on a specific vulnerability type
  vigolium agent swarm --input "https://example.com/search?q=test" --vuln-type sqli

  # Use specific scanner modules
  vigolium agent swarm --input "https://example.com/api" -m sqli -m xss -m ssti

  # Run discovery+spidering before planning
  vigolium agent swarm -t https://example.com --discover

  # Use a custom agent backend
  vigolium agent swarm --input "https://example.com" --agent gemini

  # Swarm a database record
  vigolium agent swarm --record-uuid abc123-def456

  # Add custom instructions to guide the agent
  vigolium agent swarm --input "https://example.com" --instruction "Focus on auth bypass and IDOR"

  # Load instructions from a file
  vigolium agent swarm --input "https://example.com" --instruction-file ./pentest-notes.md

  # Skip specific scan phases
  vigolium agent swarm -t https://example.com --source ./src --skip discovery,spidering

  # Limit triage-rescan iterations
  vigolium agent swarm --input "https://example.com" --max-iterations 1

  # Dry run — render prompts without executing
  vigolium agent swarm -t https://example.com --source ./src --dry-run

  # Show rendered prompts on stderr while executing
  vigolium agent swarm --input "https://example.com" --show-prompt`,
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
	f.StringVar(&swarmFocus, "focus", "", "Focus area hint for the agent (e.g. 'API injection', 'auth bypass')")
	f.StringSliceVarP(&swarmModules, "modules", "m", nil, "Explicit module names to include")
	f.IntVar(&swarmMaxIterations, "max-iterations", 3, "Maximum triage-rescan iterations")
	f.StringVar(&swarmAgentName, "agent", "", "Agent backend to use (default from config)")
	f.BoolVar(&swarmDryRun, "dry-run", false, "Render prompts without executing")
	f.BoolVar(&swarmShowPrompt, "show-prompt", false, "Print rendered prompts to stderr before executing")
	f.BoolVar(&swarmSourceAnalysisOnly, "source-analysis-only", false, "Run only the source analysis phase and exit")
	f.DurationVar(&swarmTimeout, "swarm-duration", 12*time.Hour, "Maximum swarm duration (0 = unlimited)")
	f.StringVar(&swarmProfile, "profile", "", "Scanning profile to use")
	f.StringVar(&swarmOnlyPhase, "only", "", "Run only this scanning phase (discovery, spidering, spa, audit, external-harvest)")
	f.StringSliceVar(&swarmSkipPhases, "skip", nil, "Skip specific phases (discovery, spidering, spa, audit, external-harvest, triage, rescan)")
	f.StringVar(&swarmStartFrom, "start-from", "", "Resume from a specific phase (native-normalize, source-analysis, code-audit, native-sast, native-discover, plan, native-extension, native-scan, triage)")
	f.StringVar(&swarmInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompts)")
	f.StringVar(&swarmInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.BoolVar(&swarmDiscover, "discover", false, "Run discovery+spidering before master agent planning to expand attack surface")
	f.BoolVar(&swarmCodeAudit, "code-audit", false, "Enable AI security code audit phase (on by default when --source is provided, use --code-audit=false to disable)")
	// Hidden alias for pipeline backward compatibility
	f.IntVar(&swarmMaxIterations, "max-rescan-rounds", 3, "Alias for --max-iterations (pipeline backward compatibility)")
	_ = agentSwarmCmd.Flags().MarkHidden("max-rescan-rounds")

	f.IntVar(&swarmBatchConcurrency, "batch-concurrency", 0, "Max parallel master agent batches (0 = auto, scales with CPU count)")
	f.IntVar(&swarmMaxMasterRetries, "max-master-retries", 3, "Max master agent retries on parse failure")
	f.IntVar(&swarmSubAgentConcurrency, "sub-agent-concurrency", 3, "Max parallel source analysis sub-agents (routes, auth, extensions)")
	f.IntVar(&swarmMaxPlanRecords, "max-plan-records", 10, "Max records sent to plan agent (selects most interesting; 0 = no limit)")
	f.IntVar(&swarmMasterBatchSize, "master-batch-size", 0, "Max records per master agent batch (0 = default 5)")
	f.IntVar(&swarmProbeConcurrency, "probe-concurrency", 0, "Max parallel probe requests (0 = default 10)")
	f.DurationVar(&swarmProbeTimeout, "probe-timeout", 0, "Per-request probe timeout (0 = default 10s)")
	f.IntVar(&swarmMaxProbeBody, "max-probe-body", 0, "Max response body size in bytes during probing (0 = default 2MB)")
	f.BoolVar(&swarmSkipSAST, "skip-sast", false, "Skip native SAST tools (ast-grep, osv-scanner, semgrep) during source analysis")
	f.BoolVar(&swarmTriage, "triage", false, "Enable AI triage and rescan phases (disabled by default)")

	// Browser automation
	f.BoolVar(&swarmBrowser, "browser", false, "Enable agent-browser for browser-based auth capture and interaction")
	f.BoolVar(&swarmAuth, "auth", false, "Run browser-based auth phase before discovery (requires --browser)")
	f.StringVar(&swarmCredentials, "credentials", "", "Credentials for browser auth phase (e.g. 'username=admin,password=secret')")

	// Background archon-audit
	f.StringVar(&swarmArchon, "archon", "", "Run background archon-audit for parallel security auditing: 'lite' (3-phase, default), 'scan' (6-phase), or 'deep' (11-phase). Requires --source")
	agentSwarmCmd.Flag("archon").NoOptDefVal = "lite" // bare --archon defaults to lite

}

func runAgentSwarm(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Natural language prompt: positional arg takes precedence when no explicit flags are set
	hasExplicitFlags := swarmTarget != "" || swarmInput != "" || swarmRecordUUID != "" || swarmSource != ""
	if len(args) > 0 && !hasExplicitFlags {
		return runSwarmFromPrompt(cmd, args[0])
	}

	// Validate: at least one input source (stdin is checked later in buildSwarmInputs)
	if swarmTarget == "" && swarmInput == "" && swarmRecordUUID == "" && swarmSource == "" && !stdinIsPiped() {
		return fmt.Errorf("at least one input is required: --target, --input, --record-uuid, --source, or pipe via stdin\n\nOr use a natural language prompt:\n  vigolium agent swarm \"scan source at ~/src/app on localhost:3005\"")
	}

	// Source-only mode: --source without any target/input is allowed but skips dynamic testing
	sourceOnly := swarmSource != "" && swarmTarget == "" && swarmInput == "" && swarmRecordUUID == "" && !stdinIsPiped()
	if sourceOnly {
		fmt.Fprintf(os.Stderr, "%s No --target specified. Dynamic testing (discovery, scanning, triage) will be skipped.\n",
			terminal.WarningSymbol())
		fmt.Fprintf(os.Stderr, "%s Running source-only analysis: source analysis → code audit → SAST\n",
			terminal.WarningSymbol())
		if cmd.Flags().Changed("discover") {
			fmt.Fprintf(os.Stderr, "%s --discover ignored without a target URL\n",
				terminal.WarningSymbol())
		}
	}

	// --source-analysis-only requires --source
	if swarmSourceAnalysisOnly && swarmSource == "" {
		return fmt.Errorf("--source-analysis-only requires --source")
	}

	// --auth requires --browser
	if swarmAuth && !swarmBrowser {
		return fmt.Errorf("--auth requires --browser (browser automation must be enabled for auth capture)")
	}

	// Enable code-audit by default when --source is provided
	if swarmSource != "" && !cmd.Flags().Changed("code-audit") {
		swarmCodeAudit = true
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// --browser CLI flag overrides config
	if cmd.Flags().Changed("browser") {
		enabled := swarmBrowser
		settings.Agent.Browser.Enable = &enabled
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

	// --focus is a fallback for --vuln-type
	if swarmFocus != "" && swarmVulnType == "" {
		swarmVulnType = swarmFocus
	}

	// Normalize phase names to support legacy aliases (e.g., "normalize" → "native-normalize")
	swarmStartFrom = agent.NormalizeSwarmPhase(swarmStartFrom)
	for i, p := range swarmSkipPhases {
		swarmSkipPhases[i] = agent.NormalizeSwarmPhase(p)
	}

	// Skip triage+rescan by default unless --triage is explicitly set
	if !swarmTriage && !agent.PhaseSkipped(swarmSkipPhases, agent.SwarmPhaseTriage) {
		swarmSkipPhases = append(swarmSkipPhases, agent.SwarmPhaseTriage)
	}

	// Build swarm config
	cfg := agent.SwarmConfig{
		Inputs:             inputs,
		Instruction:        instruction,
		SourcePath:         swarmSource,
		Files:              swarmFiles,
		VulnType:           swarmVulnType,
		Focus:              swarmFocus,
		ModuleNames:        swarmModules,
		OnlyPhase:          swarmOnlyPhase,
		SkipPhases:         swarmSkipPhases,
		MaxIterations:      swarmMaxIterations,
		BatchConcurrency:   swarmBatchConcurrency,
		MaxMasterRetries:   swarmMaxMasterRetries,
		SAMaxConcurrency:   swarmSubAgentConcurrency,
		MaxPlanRecords:     swarmMaxPlanRecords,
		AgentName:          swarmAgentName,
		DryRun:             swarmDryRun,
		ShowPrompt:         swarmShowPrompt,
		SourceAnalysisOnly: swarmSourceAnalysisOnly,
		CodeAudit:          swarmCodeAudit,
		Browser:            settings.Agent.Browser.IsEnabled(),
		Auth:               swarmAuth,
		Credentials:        swarmCredentials,
		SessionsDir:        settings.Agent.EffectiveSessionsDir(),
		SessionDir:         sessionDir,
		RunUUID:            swarmRunID,
		ProjectUUID:        projectUUID,
		ScanUUID:           globalScanID,
		MasterBatchSize:    swarmMasterBatchSize,
		ProbeConcurrency:   swarmProbeConcurrency,
		ProbeTimeout:       swarmProbeTimeout,
		MaxProbeBodySize:   swarmMaxProbeBody,
	}

	// Wire archon: --archon flag overrides config
	if auditCfg := agent.ResolveAuditAgentConfig(swarmArchon, settings.Agent.Archon); auditCfg != nil {
		cfg.Archon = auditCfg
	}

	// --start-from: build a synthetic checkpoint with all prior phases marked completed
	if swarmStartFrom != "" {
		syntheticCP := buildSyntheticCheckpoint(swarmStartFrom)
		if syntheticCP != nil {
			_ = agent.WriteCheckpointToDir(sessionDir, syntheticCP)
			cfg.ResumeDir = sessionDir
		}
	}

	// Only stream raw agent output to stdout in verbose/debug mode.
	// In normal mode, phase progress lines (❯ phase │ ...) and output file
	// paths are printed instead — the full LLM response is saved to the
	// session directory.
	if settings.Agent.StreamEnabled() && zap.L().Core().Enabled(zap.DebugLevel) {
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

	// Wire SAST callback automatically when --source is provided (unless --skip-sast)
	if swarmSource != "" && !swarmSkipSAST {
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
	if effectiveAgent == "" {
		effectiveAgent = settings.Agent.DefaultAgent
	}

	// Print agent configuration banner (styled like Scan Configuration)
	inputDesc := swarmTarget
	if inputDesc == "" && swarmInput != "" {
		inputDesc = truncateSwarmInput(swarmInput, 80)
	}
	if inputDesc == "" && swarmRecordUUID != "" {
		inputDesc = "record:" + swarmRecordUUID
	}

	fmt.Fprint(os.Stderr, GetBanner())
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.HiBlue(terminal.SymbolSparkle), terminal.BoldHiBlue("Agent Configuration"))

	// Mode + Agent + Model on one line
	mode := "swarm"
	if swarmSourceAnalysisOnly {
		mode = "swarm (source-analysis-only)"
	}
	// Resolve model from agent backend definition
	effectiveModel := ""
	if def, ok := settings.Agent.Backends[effectiveAgent]; ok && def.Model != "" {
		effectiveModel = def.Model
	}
	modeLine := fmt.Sprintf("  %s Mode: %s | Agent: %s",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiTeal(mode),
		terminal.HiTeal(effectiveAgent))
	if effectiveModel != "" {
		modeLine += fmt.Sprintf(" | Model: %s", terminal.HiTeal(effectiveModel))
	}
	fmt.Fprintln(os.Stderr, modeLine)

	// Prompt
	promptPath := agent.ResolveTemplatePath(agent.SwarmPromptPlan, settings.Agent.TemplatesDir)
	fmt.Fprintf(os.Stderr, "  %s Prompt: %s %s\n", terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(agent.SwarmPromptPlan), terminal.Muted(promptPath))

	// Target / Inputs
	if inputDesc != "" {
		fmt.Fprintf(os.Stderr, "  %s Target: %s\n", terminal.Purple(terminal.SymbolTarget), terminal.Orange(inputDesc))
	}

	// Source
	if swarmSource != "" {
		fmt.Fprintf(os.Stderr, "  %s Source: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(terminal.ShortenHome(swarmSource)))
	}

	// Phases — show enabled/disabled status for each swarm phase
	swarmPhaseLabel := func(name string, enabled bool) string {
		if !enabled {
			return terminal.Gray(terminal.SymbolError) + " " + terminal.Gray(name)
		}
		return terminal.Green(terminal.SymbolSuccess) + " " + terminal.HiCyan(name)
	}
	hasSource := swarmSource != ""
	hasSAST := hasSource && !swarmSkipSAST
	isSkipped := func(phase string) bool {
		for _, s := range swarmSkipPhases {
			if strings.EqualFold(s, phase) {
				return true
			}
		}
		return false
	}
	sourceAnalysisOnly := swarmSourceAnalysisOnly

	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		swarmPhaseLabel("SourceAnalysis", hasSource),
		swarmPhaseLabel("CodeAudit", swarmCodeAudit && hasSource),
		swarmPhaseLabel("SAST", hasSAST),
		swarmPhaseLabel("Discovery", swarmDiscover && !isSkipped("discovery")),
		swarmPhaseLabel("Plan", !sourceAnalysisOnly))
	fmt.Fprintf(os.Stderr, "           %s | %s | %s\n",
		swarmPhaseLabel("Scan", !sourceAnalysisOnly),
		swarmPhaseLabel("Triage", !sourceAnalysisOnly && !isSkipped("triage")),
		swarmPhaseLabel("Rescan", !sourceAnalysisOnly && !isSkipped("rescan")))

	// Vulnerability focus / focus area
	if swarmVulnType != "" {
		fmt.Fprintf(os.Stderr, "  %s Vuln focus: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.Orange(swarmVulnType))
	} else if swarmFocus != "" {
		fmt.Fprintf(os.Stderr, "  %s Focus area: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.Orange(swarmFocus))
	}

	// SAST tools detail
	if hasSAST {
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
		fmt.Fprintf(os.Stderr, "  %s SAST: %s %s\n", terminal.Purple(terminal.SymbolInfo),
			terminal.HiGreen("enabled"), terminal.Muted("("+sastTools+")"))
	}

	// Iteration limits
	durationStr := "unlimited"
	if swarmTimeout > 0 {
		durationStr = swarmTimeout.String()
	}
	fmt.Fprintf(os.Stderr, "  %s Limits: max-iterations=%s | duration=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", swarmMaxIterations)),
		terminal.HiBlue(durationStr))

	// Session dir
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "  %s Session: %s\n", terminal.Purple(terminal.SymbolInfo),
			terminal.Muted(terminal.ShortenHome(sessionDir)))
	}

	// Tips
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s Use %s to tell the agent to focus on a specific area (e.g. auth bypass, IDOR, SQLi)\n",
		terminal.TipPrefix(), terminal.Cyan("--instruction \"focus on ...\""))
	fmt.Fprintf(os.Stderr, "  %s Use %s to run discovery+spidering before planning to expand the attack surface\n",
		terminal.TipPrefix(), terminal.Cyan("--discover"))
	fmt.Fprintln(os.Stderr)

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
			fmt.Fprintf(os.Stderr, "  %s prompt: %s %s\n\n",
				terminal.FunctionSymbol(), terminal.Orange(promptName), terminal.Muted("(path="+pp+")"))
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

		// Apply generated auth config from source analysis or custom instruction.
		// Use best-effort mode: AI-generated configs may be malformed, so session
		// init errors become warnings rather than aborting the scan.
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
			opts.AuthConfigBestEffort = true
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
			settingsCopy.Audit.Extensions.ExtensionDir = req.ExtensionDir
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
			opts.AuthConfigBestEffort = true
		}

		fmt.Fprintf(os.Stderr, "%s Discovery & Spidering (expanding attack surface)\n",
			terminal.Aqua(terminal.SymbolSparkle))

		return runPhaseRunner(opts, settings, repo)
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

	// Core stats line: duration, records, findings
	parts := []string{result.Duration.Round(time.Second).String()}
	if result.TotalRecords > 0 {
		parts = append(parts, fmt.Sprintf("%d records", result.TotalRecords))
	}
	findingsStr := fmt.Sprintf("%s findings", colorFindingCount(result.TotalFindings))
	if len(result.SeverityCounts) > 0 && result.TotalFindings > 0 {
		findingsStr += " (" + formatSeverityWithSymbols(result.SeverityCounts) + ")"
	}
	parts = append(parts, findingsStr)
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Join(parts, " · "))

	// Plan summary (single line)
	if result.SwarmPlan != nil {
		planParts := []string{}
		if len(result.SwarmPlan.FocusAreas) > 0 {
			planParts = append(planParts, fmt.Sprintf("%d focus areas", len(result.SwarmPlan.FocusAreas)))
		}
		extCount := len(result.SwarmPlan.Extensions)
		if extCount > 0 {
			planParts = append(planParts, fmt.Sprintf("%d extensions", extCount))
		}
		if len(planParts) > 0 {
			fmt.Fprintf(os.Stderr, "  %s %s\n",
				terminal.Gray("Plan:"),
				terminal.Cyan(strings.Join(planParts, ", ")))
		}
	}

	// Triage summary (single line)
	if len(result.TriageResults) > 0 {
		fmt.Fprintf(os.Stderr, "  %s %s confirmed, %s false positives (%d iterations)\n",
			terminal.Gray("Triage:"),
			terminal.BoldGreen(fmt.Sprintf("%d", result.Confirmed)),
			terminal.Gray(fmt.Sprintf("%d", result.FalsePositives)),
			result.Iterations)
	}

	// Session dir with plan file pointer
	if result.SessionDir != "" {
		shortDir := terminal.ShortenHome(result.SessionDir)
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			terminal.Gray("Details:"),
			terminal.Muted(shortDir))
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
			opts.AuthConfigBestEffort = true
		}

		fmt.Fprintf(os.Stderr, "%s SAST analysis (ast-grep + secret detection + third-party tools)\n",
			terminal.GrbRed(terminal.SymbolSparkle))

		return runPhaseRunner(opts, settings, repo)
	}
}

// buildSyntheticCheckpoint creates a checkpoint with all phases before the target marked as completed.
// This enables --start-from to skip earlier phases without a real resume directory.
func buildSyntheticCheckpoint(startFrom string) *agent.SwarmCheckpoint {
	// Ordered swarm phases
	allPhases := []string{
		agent.SwarmPhaseNormalize,
		agent.SwarmPhaseSourceAnalysis,
		agent.SwarmPhaseCodeAudit,
		agent.SwarmPhaseSAST,
		agent.SwarmPhaseDiscover,
		agent.SwarmPhasePlan,
		agent.SwarmPhaseExtension,
		agent.SwarmPhaseScan,
		agent.SwarmPhaseTriage,
	}

	var completed []string
	for _, p := range allPhases {
		if p == startFrom {
			break
		}
		completed = append(completed, p)
	}

	if len(completed) == 0 {
		return nil
	}

	return &agent.SwarmCheckpoint{
		CompletedPhases: completed,
		Timestamp:       time.Now(),
	}
}

func truncateSwarmInput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// runSwarmFromPrompt parses a natural language prompt and runs swarm for each extracted app.
func runSwarmFromPrompt(cmd *cobra.Command, prompt string) error {
	intent, engine, settings, repo, err := parsePromptIntent(prompt)
	if err != nil {
		return err
	}
	defer engine.Close()
	if intent.Cleanup != nil {
		defer intent.Cleanup.Cleanup()
	}

	if swarmDryRun {
		return printIntentDryRun(intent)
	}

	// Single app: populate flags and re-enter the main flow.
	// Close the intent-parsing engine first so runAgentSwarm creates its own cleanly.
	if len(intent.Apps) == 1 {
		applyIntentToSwarmFlags(intent.Apps[0])
		engine.Close()
		return runAgentSwarm(cmd, nil)
	}

	// Multi-app: fan-out parallel runs using the already-created engine
	engine.EnsureWarmSessions()
	fmt.Fprintf(os.Stderr, "%s Parsed %d apps from prompt, running in parallel\n",
		terminal.InfoSymbol(), len(intent.Apps))
	return runMultiAppSwarm(context.Background(), cmd, engine, settings, repo, intent)
}

// applyIntentToSwarmFlags populates swarm package-level flags from an AppIntent.
func applyIntentToSwarmFlags(app agent.AppIntent) {
	swarmTarget = app.Target
	swarmSource = app.SourcePath
	if app.Discover {
		swarmDiscover = true
	}
	if app.Focus != "" && swarmFocus == "" {
		swarmFocus = app.Focus
	}
	if app.Instruction != "" && swarmInstruction == "" {
		swarmInstruction = app.Instruction
	}
	if app.Archon != "" && swarmArchon == "" {
		swarmArchon = app.Archon
	}
	fmt.Fprintf(os.Stderr, "%s Resolved: target=%s source=%s discover=%v\n",
		terminal.SuccessSymbol(),
		valueOrNone(swarmTarget),
		valueOrNone(terminal.ShortenHome(swarmSource)),
		swarmDiscover)
}

// runMultiAppSwarm fans out parallel swarm runs for multiple apps.
func runMultiAppSwarm(ctx context.Context, cmd *cobra.Command, engine *agent.Engine, settings *config.Settings, repo *database.Repository, intent *agent.ScanIntent) error {
	if swarmTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, swarmTimeout)
		defer cancel()
	}

	return runMultiAppFanOut(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		runID := "agt-" + uuid.New().String()
		sessionDir, _ := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), runID)

		instruction := mergeIntentInstruction(swarmInstruction, swarmInstructionFile, app)
		focus := swarmFocus
		if app.Focus != "" {
			focus = app.Focus
		}
		vulnType := swarmVulnType
		if focus != "" && vulnType == "" {
			vulnType = focus
		}

		fmt.Fprintf(os.Stderr, "%s [%d/%d] Starting swarm: target=%s source=%s\n",
			terminal.InfoSymbol(), idx+1, len(intent.Apps),
			valueOrNone(app.Target),
			valueOrNone(terminal.ShortenHome(app.SourcePath)))

		var inputs []string
		if app.Target != "" {
			inputs = append(inputs, app.Target)
		}

		codeAudit := swarmCodeAudit
		if app.SourcePath != "" && !cmd.Flags().Changed("code-audit") {
			codeAudit = true
		}

		projectUUID, _ := resolveProjectUUID()

		skipPhases := append([]string(nil), swarmSkipPhases...)
		if !swarmTriage && !agent.PhaseSkipped(skipPhases, agent.SwarmPhaseTriage) {
			skipPhases = append(skipPhases, agent.SwarmPhaseTriage)
		}

		var generatedAuthConfig string

		cfg := agent.SwarmConfig{
			Inputs:       inputs,
			Instruction:  instruction,
			SourcePath:   app.SourcePath,
			VulnType:     vulnType,
			Focus:        focus,
			MaxIterations: swarmMaxIterations,
			AgentName:    swarmAgentName,
			ShowPrompt:   swarmShowPrompt,
			CodeAudit:    codeAudit,
			SkipPhases:   skipPhases,
			SessionsDir:  settings.Agent.EffectiveSessionsDir(),
			SessionDir:   sessionDir,
			RunUUID:      runID,
			ProjectUUID:  projectUUID,
			ScanUUID:     globalScanID,
		}

		// Wire scan callback using per-app target (not the package-level swarmTarget)
		cfg.ScanFunc = buildMultiAppSwarmScanFunc(settings, repo, app.Target, swarmOnlyPhase, swarmSkipPhases, &generatedAuthConfig)

		if app.Discover && app.Target != "" {
			cfg.DiscoverFunc = buildMultiAppSwarmDiscoverFunc(settings, repo, app.Target, &generatedAuthConfig)
		}

		if app.SourcePath != "" && !swarmSkipSAST {
			cfg.SASTFunc = buildSwarmSASTFunc(settings, repo, app.SourcePath, &generatedAuthConfig)
		}

		swarmRunner := agent.NewSwarmRunner(engine, repo)
		_, runErr := swarmRunner.Run(ctx, cfg)
		return runErr
	})
}

// buildMultiAppSwarmScanFunc is like buildAgentSwarmScanFunc but takes an explicit
// target parameter instead of closing over the package-level swarmTarget.
// This is necessary for multi-app fan-out where each goroutine has a different target.
func buildMultiAppSwarmScanFunc(settings *config.Settings, repo *database.Repository, target string, onlyPhase string, skipPhases []string, authConfigPath *string) agent.ScanFunc {
	return func(ctx context.Context, req agent.ScanRequest) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{target}
		opts.ScanUUID = globalScanID
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		opts.ProjectUUID = projectUUID
		opts.ConfigPath = globalConfig
		opts.HeuristicsCheck = "none"
		opts.PassiveModules = []string{"all"}

		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
			opts.AuthConfigBestEffort = true
		}

		if req.IsRescan {
			opts.OnlyPhase = "audit"
			opts.SkipIngestion = true
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
		} else {
			opts.Modules = []string{"all"}
			if onlyPhase != "" {
				opts.OnlyPhase = onlyPhase
			}
			if len(skipPhases) > 0 {
				opts.SkipPhases = skipPhases
			}
		}

		opts.Verbose = globalVerbose

		settingsCopy := *settings
		if req.ExtensionDir != "" {
			settingsCopy.Audit.Extensions.Enabled = true
			settingsCopy.Audit.Extensions.ExtensionDir = req.ExtensionDir
		}

		fmt.Fprintf(os.Stderr, "%s Scanning %s with modules: %s\n",
			terminal.GrbRed(terminal.SymbolSparkle), target,
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

// buildMultiAppSwarmDiscoverFunc is like buildSwarmDiscoverFunc but takes an explicit
// target parameter instead of closing over the package-level swarmTarget.
func buildMultiAppSwarmDiscoverFunc(settings *config.Settings, repo *database.Repository, target string, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{target}
		opts.ScanUUID = globalScanID
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		opts.ProjectUUID = projectUUID
		opts.ConfigPath = globalConfig
		opts.HeuristicsCheck = "none"
		opts.Silent = true
		opts.ScanConfigPrinted = true

		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthConfigPath = *authConfigPath
			opts.AuthConfigBestEffort = true
		}

		fmt.Fprintf(os.Stderr, "%s Discovery+spidering for %s (crawl, JS analysis, external harvesting)\n",
			terminal.GrbRed(terminal.SymbolSparkle), target)

		return runPhaseRunner(opts, settings, repo)
	}
}

// runPhaseRunner creates a runner with the given options, executes it, and cleans up.
func runPhaseRunner(opts *types.Options, settings *config.Settings, repo *database.Repository) error {
	scanRunner, err := runner.New(opts)
	if err != nil {
		return err
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)
	return scanRunner.RunNativeScan()
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
	Extract     []extractRuleYAML `yaml:"extract,omitempty"`
	Type        string            `yaml:"type,omitempty"`
	TokenPath   string            `yaml:"token_path,omitempty"`
	Expect      *expectYAML       `yaml:"expect,omitempty"`
}

type expectYAML struct {
	Status       []int  `yaml:"status,omitempty"`
	BodyContains string `yaml:"body_contains,omitempty"`
}

type extractRuleYAML struct {
	Source  string `yaml:"source"`
	Name    string `yaml:"name,omitempty"`
	Path    string `yaml:"path,omitempty"`
	ApplyAs string `yaml:"apply_as,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
	Group   int    `yaml:"group,omitempty"`
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
				Type:        s.Login.Type,
				TokenPath:   s.Login.TokenPath,
			}
			if s.Login.Expect != nil {
				login.Expect = &expectYAML{
					Status:       s.Login.Expect.Status,
					BodyContains: s.Login.Expect.BodyContains,
				}
			}
			for _, e := range s.Login.Extract {
				login.Extract = append(login.Extract, extractRuleYAML{
					Source:  e.Source,
					Name:    e.Name,
					Path:    e.Path,
					ApplyAs: e.ApplyAs,
					Pattern: e.Pattern,
					Group:   e.Group,
				})
			}
			entry.Login = login
		}
		result.Sessions = append(result.Sessions, entry)
	}
	return result
}
