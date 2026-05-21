package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

// agent swarm command flags
var (
	swarmTarget              string
	swarmInput               string
	swarmRecordUUIDs         []string
	swarmAllRecords          bool
	swarmRecordsFrom         string
	swarmSource              string
	swarmFiles               []string
	swarmVulnType            string
	swarmFocus               string
	swarmModules             []string
	swarmMaxIterations       int
	swarmAgentLabel          string
	swarmDryRun              bool
	swarmShowPrompt          bool
	swarmSourceAnalysisOnly  bool
	swarmMaxDuration         time.Duration
	swarmProfile             string
	swarmOnlyPhase           string
	swarmSkipPhases          []string
	swarmStartFrom           string
	swarmInstruction         string
	swarmInstructionFile     string
	swarmPlanFile            string
	swarmPlanInputs          []string
	swarmDiscover            bool
	swarmBatchConcurrency    int
	swarmMaxMasterRetries    int
	swarmSubAgentConcurrency int
	swarmCodeAudit           bool
	swarmTriage              bool
	swarmForceExtensions     bool
	swarmMaxPlanRecords      int
	swarmMasterBatchSize     int
	swarmProbeConcurrency    int
	swarmProbeTimeout        time.Duration
	swarmMaxProbeBody        int
	swarmBrowser             bool
	swarmBrowserAuth         bool
	swarmAuthCookies         []string
	swarmAuthHeaders         []string
	swarmLoginCurl           string
	swarmAuthConfigPath      string
	swarmCredentials         string
	swarmCredentialSets      []agent.IntentCredentialSet
	swarmBrowserAuthRequired bool
	swarmRequiresBrowser     bool
	swarmBrowserStartURL     string
	swarmFocusRoutes         []string
	swarmAudit              string
	swarmPiolium             string
	swarmDiff                string
	swarmLastCommits         int
	swarmIntensity           string
	swarmUploadResults       bool
	swarmDisableGuardrail    bool
	swarmVerbose             bool

	// swarmInstructionPrefix holds the verbatim natural-language prompt when
	// swarm was invoked with a positional `<prompt>` argument. See the
	// matching autopilotInstructionPrefix comment for the rationale.
	swarmInstructionPrefix string
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
  vigolium agent swarm "Hunt SSRF on https://target/api — only credentialed paths under /v2/billing count"

The prompt is parsed by an AI to extract target URLs, source paths, and focus
areas, AND is also forwarded verbatim to the master/sub-agents as their
primary instruction so nuanced hints (scope caveats, exploitation goals,
false-positive rules) survive unedited. --instruction / --instruction-file,
if supplied, is appended after the verbatim prompt. Use --dry-run to
preview what the parser extracts without executing.

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)
  - Record UUID: abc123-... (from http_records table)

When input is piped via stdin, it is automatically read (no --input needed).

Plan file (--plan-file): a single file mixing free-text guidance and raw
HTTP request(s). Prose before the first request becomes the instruction; the
request region (split on lines that are exactly "---", or fenced ` + "```http```" + `
blocks) supplies the seed requests. The swarm feeds every request block as an
independent seed input. --plan-file cannot be combined with --input/
--instruction/--instruction-file:
  vigolium agent swarm --plan-file ginandjuice-plan.md

Intensity presets (--intensity) bundle multiple settings into a single flag:
  quick     — Fast scan: discovery + browser, no triage, 2h limit, 1 iteration
  balanced  — Standard scan (default): discovery + browser + triage, code audit if source, 12h limit
  deep      — Thorough scan: discovery + browser + auth + triage, 24h limit, 5 iterations

Explicit flags always override intensity presets.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgentSwarm,
}

func init() {
	agentCmd.AddCommand(agentSwarmCmd)
	f := agentSwarmCmd.Flags()

	f.StringVarP(&swarmTarget, "target", "t", "", "Target URL (required when --source is used)")
	f.StringVar(&swarmInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringSliceVar(&swarmRecordUUIDs, "record-uuid", nil, "HTTP record UUID from database (repeatable, or comma-separated)")
	f.BoolVar(&swarmAllRecords, "all-records", false, "Use every HTTP record in the active project as input")
	f.StringVar(&swarmRecordsFrom, "records-from", "", "Filter ingested HTTP records by spec (e.g. \"host=example.com,status=200,method=GET,path=/api,since=2026-04-01\")")
	f.StringVar(&swarmSource, "source", "", "Path to application source code for route discovery")
	f.StringSliceVar(&swarmFiles, "files", nil, "Specific source files to include (relative to --source)")
	f.StringVar(&swarmVulnType, "vuln-type", "", "Vulnerability type focus (e.g. sqli, xss, ssrf)")
	f.StringVar(&swarmFocus, "focus", "", "Focus area hint for the agent (e.g. 'API injection', 'auth bypass')")
	f.StringSliceVarP(&swarmModules, "modules", "m", nil, "Explicit module names to include")
	f.IntVar(&swarmMaxIterations, "max-iterations", 3, "Maximum triage-rescan iterations")
	f.StringVar(&swarmAgentLabel, "agent-label", "", "Label recorded on the AgenticScan DB row; agent dispatch always uses olium")
	f.BoolVar(&swarmDryRun, "dry-run", false, "Render prompts without executing")
	f.BoolVar(&swarmShowPrompt, "show-prompt", false, "Print rendered prompts to stderr before executing")
	f.BoolVar(&swarmSourceAnalysisOnly, "source-analysis-only", false, "Run only the source analysis phase and exit")
	f.DurationVar(&swarmMaxDuration, "max-duration", 12*time.Hour, "Maximum swarm duration (0 = unlimited; e.g. 6h, 24h)")
	f.StringVar(&swarmProfile, "profile", "", "Scanning profile to use")
	f.StringVar(&swarmOnlyPhase, "only", "", "Run only this scanning phase (discovery, spidering, spa, dynamic-assessment, external-harvest)")
	f.StringSliceVar(&swarmSkipPhases, "skip", nil, "Skip specific phases (recon, discovery, spidering, spa, dynamic-assessment, external-harvest, triage, rescan)")
	f.StringVar(&swarmStartFrom, "start-from", "", "Resume from a specific phase (native-normalize, source-analysis, code-audit, native-discover, native-recon, plan, native-extension, native-scan, triage)")
	f.StringVar(&swarmInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompts)")
	f.StringVar(&swarmInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.StringVar(&swarmPlanFile, "plan-file", "", "Path to a plan file mixing free-text guidance and raw HTTP request(s). Every request block becomes a seed input; cannot be combined with --input/--instruction/--instruction-file")
	f.BoolVar(&swarmDiscover, "discover", false, "Run discovery+spidering before master agent planning to expand attack surface")
	f.BoolVar(&swarmCodeAudit, "code-audit", false, "Enable AI security code audit phase (on by default when --source is provided, use --code-audit=false to disable)")
	// Hidden alias for pipeline backward compatibility
	f.IntVar(&swarmMaxIterations, "max-rescan-rounds", 3, "Alias for --max-iterations (pipeline backward compatibility)")
	_ = agentSwarmCmd.Flags().MarkHidden("max-rescan-rounds")

	f.IntVar(&swarmBatchConcurrency, "batch-concurrency", 0, "Max parallel master agent batches (0 = auto, scales with CPU count)")
	f.IntVar(&swarmMaxMasterRetries, "max-master-retries", 3, "Max master agent retries on parse failure")
	f.IntVar(&swarmSubAgentConcurrency, "sub-agent-concurrency", 3, "Max parallel source analysis sub-agents (routes, auth, extensions)")
	f.IntVar(&swarmMaxPlanRecords, "max-plan-records", 25, "Max records sent to plan agent (selects most interesting with one slot per URL prefix; 0 = no limit). Defaults are overridden by --intensity: quick=10, balanced=25, deep=50.")
	f.IntVar(&swarmMasterBatchSize, "master-batch-size", 0, "Max records per master agent batch (0 = default 5)")
	f.IntVar(&swarmProbeConcurrency, "probe-concurrency", 0, "Max parallel probe requests (0 = default 10)")
	f.DurationVar(&swarmProbeTimeout, "probe-timeout", 0, "Per-request probe timeout (0 = default 10s)")
	f.IntVar(&swarmMaxProbeBody, "max-probe-body", 0, "Max response body size in bytes during probing (0 = default 2MB)")
	f.BoolVar(&swarmTriage, "triage", false, "Enable AI triage and rescan phases. Intensity preset overrides this: balanced/deep enable triage by default; quick disables it. Use --triage=false to force-disable on balanced/deep.")
	f.BoolVar(&swarmForceExtensions, "with-extensions", false, "Force the extension agent to run even when the planner decides built-in modules are sufficient (no effect with --dry-run)")

	// Browser automation
	f.BoolVar(&swarmBrowser, "browser", false, "Enable agent-browser for browser-based auth capture and interaction")
	f.BoolVar(&swarmBrowserAuth, "browser-auth", false, "Run browser-based auth phase before discovery (requires --browser)")
	f.StringVar(&swarmCredentials, "credentials", "", "Credentials for browser auth phase (e.g. 'username=admin,password=secret')")

	// Direct auth injection — bypass the browser when you already have a session.
	f.StringSliceVar(&swarmAuthCookies, "cookie", nil, "Session cookie name=value pair (repeatable; e.g. --cookie 'session=abc123'). Injected into recon, discovery, and scan as Cookie: header.")
	f.StringSliceVarP(&swarmAuthHeaders, "header", "H", nil, "Inject HTTP header into recon, discovery, and scan (repeatable; e.g. -H 'Authorization: Bearer xxx').")
	f.StringVar(&swarmLoginCurl, "login-curl", "", "Curl command for login flow; replayed by the auth runtime to capture a fresh session. Cookies/headers from a successful response are reused for the scan.")
	f.StringVar(&swarmAuthConfigPath, "auth-config", "", "Path to an existing auth-config.yaml. Skips both browser auth and --cookie/--header/--login-curl synthesis.")

	// Background vigolium-audit
	f.StringVar(&swarmAudit, "audit", "", "Run background vigolium-audit for parallel security auditing: 'lite' (3-phase, default), 'scan' (6-phase), or 'deep' (11-phase). Requires --source")
	agentSwarmCmd.Flag("audit").NoOptDefVal = "lite" // bare --audit defaults to lite
	f.StringVar(&swarmPiolium, "piolium", "", "Run background piolium audit (Pi runtime): lite, balanced, deep, longshot, etc. Requires --source. Empty triggers auto-pick when --audit is also empty (piolium when pi is installed, else nothing)")
	agentSwarmCmd.Flag("piolium").NoOptDefVal = "lite"

	// Diff context
	f.StringVar(&swarmDiff, "diff", "", "Focus on changed code: PR URL (github.com/.../pull/123), git ref range (main...branch), or HEAD~N")
	f.IntVar(&swarmLastCommits, "last-commits", 0, "Focus on last N commits (shorthand for --diff HEAD~N)")

	// Intensity
	f.StringVar(&swarmIntensity, "intensity", "balanced", "Scan intensity preset: quick, balanced, or deep")

	f.BoolVar(&swarmUploadResults, "upload-results", false, "Upload scan results to cloud storage after completion (requires storage config)")
	f.BoolVar(&swarmDisableGuardrail, "disable-guardrail", false, "Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt)")
	f.BoolVarP(&swarmVerbose, "verbose", "v", false, "Show a per-tool head/tail preview of each tool result alongside the standard one-liner")
}

func runAgentSwarm(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Natural language prompt: positional arg takes precedence when no explicit flags are set
	hasExplicitFlags := swarmTarget != "" || swarmInput != "" || len(swarmRecordUUIDs) > 0 || swarmAllRecords || swarmRecordsFrom != "" || swarmSource != "" || swarmPlanFile != ""
	if len(args) > 0 && !hasExplicitFlags {
		return runSwarmFromPrompt(cmd, args[0])
	}

	// Resolve --plan-file into --instruction + seed inputs before the input
	// guards run. Swarm is multi-seed: every request block in the plan file
	// becomes an independent seed input (appended in buildSwarmInputs).
	if swarmPlanFile != "" {
		planInstruction, planRequests, perr := resolvePlanFile(
			swarmPlanFile, swarmInput, swarmInstruction, swarmInstructionFile)
		if perr != nil {
			return perr
		}
		swarmInstruction = planInstruction
		swarmPlanInputs = planRequests
	}

	// Validate: at least one input source (stdin is checked later in buildSwarmInputs)
	if swarmTarget == "" && swarmInput == "" && len(swarmRecordUUIDs) == 0 && !swarmAllRecords && swarmRecordsFrom == "" && swarmSource == "" && len(swarmPlanInputs) == 0 && !stdinIsPiped() {
		return fmt.Errorf("at least one input is required: --target, --input, --record-uuid, --all-records, --records-from, --source, --plan-file, or pipe via stdin\n\nOr use a natural language prompt:\n  vigolium agent swarm \"scan source at ~/src/app on localhost:3005\"")
	}

	// Source-only mode: --source without any target/input is allowed but skips dynamic testing
	sourceOnly := swarmSource != "" && swarmTarget == "" && swarmInput == "" && len(swarmRecordUUIDs) == 0 && !swarmAllRecords && swarmRecordsFrom == "" && len(swarmPlanInputs) == 0 && !stdinIsPiped()
	if sourceOnly {
		fmt.Fprintf(os.Stderr, "%s No --target specified. Dynamic testing (discovery, scanning, triage) will be skipped.\n",
			terminal.WarningSymbol())
		fmt.Fprintf(os.Stderr, "%s Running source-only analysis: source analysis → code audit\n",
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

	// --browser-auth requires --browser (checked after intensity resolution below)

	// Resolve intensity preset — apply before other flag processing
	intensity, intensityErr := agent.ValidateIntensity(swarmIntensity)
	if intensityErr != nil {
		return intensityErr
	}
	{
		changed := map[string]bool{
			"discover":          cmd.Flags().Changed("discover"),
			"code-audit":        cmd.Flags().Changed("code-audit"),
			"triage":            cmd.Flags().Changed("triage"),
			"max-iterations":    cmd.Flags().Changed("max-iterations"),
			"audit":            cmd.Flags().Changed("audit"),
			"max-plan-records":  cmd.Flags().Changed("max-plan-records"),
			"master-batch-size": cmd.Flags().Changed("master-batch-size"),
			"batch-concurrency": cmd.Flags().Changed("batch-concurrency"),
			"probe-concurrency": cmd.Flags().Changed("probe-concurrency"),
			"browser":           cmd.Flags().Changed("browser"),
			"browser-auth":      cmd.Flags().Changed("browser-auth"),
			"swarm-duration":    cmd.Flags().Changed("max-duration"),
		}
		intensityResult := agent.ResolveSwarmIntensity(intensity, agent.SwarmIntensityPreset{
			Discover:         swarmDiscover,
			CodeAudit:        swarmCodeAudit,
			Triage:           swarmTriage,
			MaxIterations:    swarmMaxIterations,
			Audit:           swarmAudit,
			MaxPlanRecords:   swarmMaxPlanRecords,
			MasterBatchSize:  swarmMasterBatchSize,
			BatchConcurrency: swarmBatchConcurrency,
			ProbeConcurrency: swarmProbeConcurrency,
			Browser:          swarmBrowser,
			Auth:             swarmBrowserAuth,
			SwarmDuration:    swarmMaxDuration,
		}, changed)
		swarmDiscover = intensityResult.Discover
		swarmCodeAudit = intensityResult.CodeAudit
		swarmTriage = intensityResult.Triage
		swarmMaxIterations = intensityResult.MaxIterations
		swarmAudit = intensityResult.Audit
		swarmMaxPlanRecords = intensityResult.MaxPlanRecords
		swarmMasterBatchSize = intensityResult.MasterBatchSize
		swarmBatchConcurrency = intensityResult.BatchConcurrency
		swarmProbeConcurrency = intensityResult.ProbeConcurrency
		swarmBrowser = intensityResult.Browser
		swarmBrowserAuth = intensityResult.Auth
		swarmMaxDuration = intensityResult.SwarmDuration

		// Same auto-pick rule as autopilot.
		auditChanged := cmd.Flags().Changed("audit")
		pioliumChanged := cmd.Flags().Changed("piolium")
		switch {
		case !auditChanged && !pioliumChanged && piolium.IsAvailable():
			// Move whatever audit mode the intensity preset picked over to
			// piolium; default to lite if audit was empty.
			if swarmAudit != "" {
				swarmPiolium = swarmAudit
			} else {
				swarmPiolium = "lite"
			}
			swarmAudit = ""
		case pioliumChanged && !auditChanged:
			swarmAudit = ""
		}
	}

	// --browser-auth requires --browser
	if swarmBrowserAuth && !swarmBrowser {
		return fmt.Errorf("--browser-auth requires --browser (browser automation must be enabled for auth capture)")
	}

	// Enable code-audit by default when --source is provided (unless intensity already set it)
	if swarmSource != "" && !cmd.Flags().Changed("code-audit") && !cmd.Flags().Changed("intensity") {
		swarmCodeAudit = true
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}
	// Layer the global --ext / --ext-dir flags onto settings so user-supplied
	// extensions ride alongside any agent-generated ones in the swarm pipeline.
	applyGlobalExtFlagsToSettings(settings)

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

	// Create agent engine (olium-backed, in-process).
	engine := agent.NewEngine(settings, repo)

	// Resolve project UUID
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	instruction, instrErr := resolveInstruction(swarmInstruction, swarmInstructionFile)
	if instrErr != nil {
		return instrErr
	}
	instruction = prependVerbatimPrompt(instruction, swarmInstructionPrefix)

	// Build inputs list (resolves --all-records / --records-from against the DB)
	inputs, err := buildSwarmInputs(ctx, repo, projectUUID)
	if err != nil {
		return err
	}

	// Derive swarmTarget from the first input when -t/--target wasn't supplied.
	// The discovery callback below closes over swarmTarget, so an empty value
	// here turns into opts.Targets = []string{""} and wastes a spider pass on
	// an empty host before the DB-derived target rescues the run.
	if swarmTarget == "" && len(inputs) > 0 {
		if derived, derr := agent.TargetURLFromInput(ctx, inputs[0], "", repo); derr == nil && derived != "" {
			swarmTarget = derived
		}
	}

	// Create session directory upfront so callbacks can write to it.
	// --scan-uuid pins the run for cross-node sync; otherwise mint fresh.
	swarmAgenticScanUUID := pinnedOrNewUUID(globalScanUUID)
	sessionDir, sdErr := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), swarmAgenticScanUUID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}

	if storage.IsGCSURI(swarmSource) {
		extractedPath, cleanup, gcsErr := storage.ResolveGCSSource(&settings.Storage, swarmSource, projectUUID)
		if gcsErr != nil {
			return fmt.Errorf("failed to resolve gs:// source: %w", gcsErr)
		}
		defer cleanup()
		swarmSource = extractedPath
	}

	// Resolve source (git URL, archive, local path) and diff context
	var swarmDiffCtx *agenttypes.DiffContext
	if swarmSource != "" || swarmDiff != "" || swarmLastCommits > 0 {
		var err error
		swarmSource, swarmFiles, swarmDiffCtx, err = agent.ResolveSourceAndDiff(
			swarmSource, swarmDiff, swarmLastCommits, swarmFiles, sessionDir)
		if err != nil {
			return err
		}
	}

	// Track generated auth config path (set by SourceAnalysisCallback, used by scan callbacks)
	var generatedAuthConfig string
	var reconExtraHeaders map[string]string

	// Inline auth injection (--auth-config / --cookie / --header / --login-curl).
	// Resolved before any phase so recon, discovery, and scan all see the
	// session. When --auth-config is given, we use it verbatim; otherwise we
	// synthesize an AgentSessionConfig from the inline flags.
	switch {
	case swarmAuthConfigPath != "":
		generatedAuthConfig = swarmAuthConfigPath
		zap.L().Info("Using operator-supplied auth-config", zap.String("path", generatedAuthConfig))
	case len(swarmAuthCookies) > 0 || len(swarmAuthHeaders) > 0 || swarmLoginCurl != "":
		cfg, synthErr := agent.SynthesizeAuthConfig(swarmAuthCookies, swarmAuthHeaders, swarmLoginCurl)
		if synthErr != nil {
			return fmt.Errorf("synthesize auth config: %w", synthErr)
		}
		if cfg != nil {
			authPath, writeErr := agent.WriteAuthConfigYAML(sessionDir, cfg)
			if writeErr != nil {
				return fmt.Errorf("write synthesized auth-config.yaml: %w", writeErr)
			}
			generatedAuthConfig = authPath
			reconExtraHeaders = agent.ExtraHeadersFromAuth(cfg)
			zap.L().Info("Synthesized auth-config from CLI flags",
				zap.String("path", authPath),
				zap.Int("cookies", len(swarmAuthCookies)),
				zap.Int("headers", len(swarmAuthHeaders)),
				zap.Bool("login_curl", swarmLoginCurl != ""))
			// When the operator pre-supplies auth, skip the browser auth
			// phase — running it would clobber the session they just gave us.
			if swarmBrowserAuth {
				zap.L().Info("Disabling --browser-auth because inline auth flags were provided")
				swarmBrowserAuth = false
			}
		}
	}

	// --focus is a fallback for --vuln-type
	if swarmFocus != "" && swarmVulnType == "" {
		swarmVulnType = swarmFocus
	}

	// Normalize phase names to support legacy aliases (e.g., "normalize" → "native-normalize")
	swarmStartFrom = agent.NormalizeSwarmPhase(swarmStartFrom)
	for i, p := range swarmSkipPhases {
		swarmSkipPhases[i] = agent.NormalizeSwarmPhase(p)
	}

	// Append SwarmPhaseTriage to the skip list when triage is off after
	// intensity resolution. quick → off, balanced/deep → on (preset
	// default); the user can flip either side with --triage / --triage=false.
	if !swarmTriage && !agent.PhaseSkipped(swarmSkipPhases, agent.SwarmPhaseTriage) {
		swarmSkipPhases = append(swarmSkipPhases, agent.SwarmPhaseTriage)
	}

	// Build swarm config
	cfg := agent.SwarmConfig{
		Inputs:             inputs,
		Instruction:        instruction,
		SourcePath:         swarmSource,
		Files:              swarmFiles,
		DiffContext:        swarmDiffCtx,
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
		AgentName:          swarmAgentLabel,
		DryRun:             swarmDryRun,
		ShowPrompt:         swarmShowPrompt,
		SourceAnalysisOnly: swarmSourceAnalysisOnly,
		CodeAudit:          swarmCodeAudit,
		ForceExtensions:    swarmForceExtensions,
		Browser:            settings.Agent.Browser.IsEnabled(),
		Auth:               swarmBrowserAuth,
		Credentials:        swarmCredentials,
		CredentialSets:     append([]agent.IntentCredentialSet(nil), swarmCredentialSets...),
		AuthRequired:       swarmBrowserAuthRequired,
		RequiresBrowser:    swarmRequiresBrowser,
		BrowserStartURL:    swarmBrowserStartURL,
		FocusRoutes:        append([]string(nil), swarmFocusRoutes...),
		SessionsDir:        settings.Agent.EffectiveSessionsDir(),
		SessionDir:         sessionDir,
		AgenticScanUUID:    swarmAgenticScanUUID,
		ProjectUUID:        projectUUID,
		ScanUUID:           globalScanUUID,
		MasterBatchSize:    swarmMasterBatchSize,
		ProbeConcurrency:   swarmProbeConcurrency,
		ProbeTimeout:       swarmProbeTimeout,
		MaxProbeBodySize:   swarmMaxProbeBody,
		ReconExtraHeaders:  reconExtraHeaders,
	}

	// Wire audit harness. Swarm is opt-in: empty/"off" audit means no
	// audit unless --piolium opted in (or auto-pick moved a mode over).
	swarmNoAudit := swarmAudit == "" || swarmAudit == "off"
	swarmAuditDriverMode := swarmAudit
	if swarmNoAudit {
		swarmAuditDriverMode = ""
	}
	if auditCfg, harness := agent.PickAuditHarness(swarmPiolium, swarmAuditDriverMode, swarmNoAudit, swarmSource, settings.Agent.Audit); auditCfg != nil {
		cfg.Audit = auditCfg
		cfg.AuditHarness = harness
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
	cfg.Verbose = swarmVerbose
	// Always persist the stream to {sessionDir}/runtime.log — even in
	// non-verbose mode — so `vigolium log <uuid>` can replay it later.
	if tee, closer := teeToRuntimeLog(cfg.StreamWriter, sessionDir); closer != nil {
		cfg.StreamWriter = tee
		defer func() { _ = closer.Close() }()
	}

	// Wire source analysis callback to process session config into auth-config.yaml
	cfg.SourceAnalysisCallback = func(saResult *agent.SourceAnalysisResult) error {
		if saResult.SessionConfig != nil && len(saResult.SessionConfig.Sessions) > 0 {
			authPath, writeErr := agent.WriteAuthConfigYAML(sessionDir, saResult.SessionConfig)
			if writeErr != nil {
				return writeErr
			}
			generatedAuthConfig = authPath
			zap.L().Info("Generated auth config written",
				zap.String("path", authPath),
				zap.Int("sessions", len(saResult.SessionConfig.Sessions)))
		}
		return nil
	}

	// Plumb browser-auth output into the same generatedAuthConfig slot so
	// the discovery + scan funcs see the captured session. Without this,
	// the auth phase's auth-config.yaml sits on disk unused.
	cfg.BrowserAuthCallback = newBrowserAuthCallback(&generatedAuthConfig, "")

	// Wire scan callback with auth config support
	phaseCfg := swarmNativePhaseConfig{
		Target:      swarmTarget,
		ProjectUUID: projectUUID,
		ScanUUID:    globalScanUUID,
		ConfigPath:  globalConfig,
		Verbose:     globalVerbose,
	}

	cfg.ScanFunc = buildAgentSwarmScanFunc(settings, repo, phaseCfg, swarmOnlyPhase, swarmSkipPhases, &generatedAuthConfig)

	// Wire optional discovery callback
	if swarmDiscover {
		cfg.DiscoverFunc = buildSwarmDiscoverFunc(settings, repo, phaseCfg, &generatedAuthConfig)
	}

	// Set up timeout
	if swarmMaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, swarmMaxDuration)
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
	if inputDesc == "" && len(swarmRecordUUIDs) > 0 {
		if len(swarmRecordUUIDs) == 1 {
			inputDesc = "record:" + swarmRecordUUIDs[0]
		} else {
			inputDesc = fmt.Sprintf("records:%d", len(swarmRecordUUIDs))
		}
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue("Agent Configuration"))

	// Mode + Agent + Model on one line
	mode := "swarm"
	if swarmSourceAnalysisOnly {
		mode = "swarm (source-analysis-only)"
	}
	// Resolve model from the olium config for banner display.
	effectiveModel := settings.Agent.Olium.Model
	modeLine := fmt.Sprintf("  %s Mode: %s | Agent: %s",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiTeal(mode),
		terminal.HiTeal(effectiveAgent))
	if effectiveModel != "" {
		modeLine += fmt.Sprintf(" | Model: %s", terminal.HiTeal(effectiveModel))
	}
	fmt.Fprintln(os.Stderr, modeLine)

	// Intensity
	fmt.Fprintf(os.Stderr, "  %s Intensity: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(swarmIntensity))

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

	// Diff
	if swarmDiffCtx != nil {
		fmt.Fprintf(os.Stderr, "  %s Diff: %s (%d changed files)\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(swarmDiffCtx.DiffRef),
			len(swarmDiffCtx.ChangedFiles))
	}

	// Phases — show enabled/disabled status for each swarm phase
	swarmPhaseLabel := func(name string, enabled bool) string {
		if !enabled {
			return terminal.Gray(terminal.SymbolError) + " " + terminal.Gray(name)
		}
		return terminal.Green(terminal.SymbolSuccess) + " " + terminal.HiCyan(name)
	}
	hasSource := swarmSource != ""
	isSkipped := func(phase string) bool {
		for _, s := range swarmSkipPhases {
			if strings.EqualFold(s, phase) {
				return true
			}
		}
		return false
	}
	sourceAnalysisOnly := swarmSourceAnalysisOnly

	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		swarmPhaseLabel("SourceAnalysis", hasSource),
		swarmPhaseLabel("CodeAudit", swarmCodeAudit && hasSource),
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

	// Iteration limits
	durationStr := "unlimited"
	if swarmMaxDuration > 0 {
		durationStr = swarmMaxDuration.String()
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
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("Use"), terminal.Cyan("--instruction \"focus on ...\""), terminal.Gray("to tell the agent to focus on a specific area (e.g. auth bypass, IDOR, SQLi)"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("Use"), terminal.Cyan("--discover"), terminal.Gray("to run discovery+spidering before planning to expand the attack surface"))
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
		webhook.FireAgenticScan(settings, repo, swarmAgenticScanUUID)
		return fmt.Errorf("agent swarm failed: %w", err)
	}

	printSwarmResult(result)

	if swarmUploadResults {
		uploadAgenticScanResults(settings, projectUUID, swarmAgenticScanUUID, sessionDir, repo)
	}

	webhook.FireAgenticScan(settings, repo, swarmAgenticScanUUID)

	return nil
}

func buildSwarmInputs(ctx context.Context, repo *database.Repository, projectUUID string) ([]string, error) {
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

	// Plan-file request blocks: each is an independent raw HTTP seed.
	inputs = append(inputs, swarmPlanInputs...)

	for _, uuid := range swarmRecordUUIDs {
		uuid = strings.TrimSpace(uuid)
		if uuid != "" {
			inputs = append(inputs, uuid)
		}
	}

	if swarmAllRecords {
		uuids, err := expandProjectRecordsFromQuery(ctx, repo, database.QueryFilters{ProjectUUID: projectUUID})
		if err != nil {
			return nil, fmt.Errorf("--all-records: %w", err)
		}
		if len(uuids) == 0 {
			return nil, fmt.Errorf("--all-records: no HTTP records in project %s", projectUUID)
		}
		fmt.Fprintf(os.Stderr, "%s --all-records expanded to %d HTTP records from project\n",
			terminal.InfoSymbol(), len(uuids))
		inputs = append(inputs, uuids...)
	}

	if swarmRecordsFrom != "" {
		filters, err := parseRecordsFromSpec(swarmRecordsFrom, projectUUID)
		if err != nil {
			return nil, fmt.Errorf("--records-from: %w", err)
		}
		uuids, err := expandProjectRecordsFromQuery(ctx, repo, filters)
		if err != nil {
			return nil, fmt.Errorf("--records-from: %w", err)
		}
		if len(uuids) == 0 {
			return nil, fmt.Errorf("--records-from %q matched 0 records in project %s", swarmRecordsFrom, projectUUID)
		}
		fmt.Fprintf(os.Stderr, "%s --records-from %q matched %d HTTP records\n",
			terminal.InfoSymbol(), swarmRecordsFrom, len(uuids))
		inputs = append(inputs, uuids...)
	}

	// Auto-detect stdin when no explicit input is provided
	if len(inputs) == 0 {
		if data, ok := readStdinIfPiped(); ok {
			inputs = append(inputs, data)
		}
	}

	return dedupeStrings(inputs), nil
}

type swarmNativePhaseConfig struct {
	Target      string
	ProjectUUID string
	ScanUUID    string
	ConfigPath  string
	Verbose     bool
}

// newBrowserAuthCallback returns a closure that stores the auth-config.yaml
// path produced by the swarm's browser-auth phase into the shared
// generatedAuthConfig slot so downstream discovery + scan funcs see it.
// appTarget is non-empty only on the multi-app code path; included in the
// log line for cross-app debugging.
func newBrowserAuthCallback(generatedAuthConfig *string, appTarget string) func(string) error {
	return func(authConfigPath string) error {
		if authConfigPath == "" {
			return nil
		}
		*generatedAuthConfig = authConfigPath
		fields := []zap.Field{zap.String("path", authConfigPath)}
		if appTarget != "" {
			fields = append(fields, zap.String("app_target", appTarget))
		}
		zap.L().Info("Browser auth config wired into discovery/scan", fields...)
		return nil
	}
}

// buildAgentSwarmScanFunc creates a callback that runs the scan.
// When IsRescan=false, it runs a full scan (all phases, all modules) by default.
// When IsRescan=true, it restricts to dynamic-assessment with targeted modules.
// The onlyPhase and skipPhases parameters allow user control via --only/--skip flags.
// authConfigPath points to a generated auth-config.yaml from source analysis (may be empty).
func buildAgentSwarmScanFunc(settings *config.Settings, repo *database.Repository, phaseCfg swarmNativePhaseConfig, onlyPhase string, skipPhases []string, authConfigPath *string) agent.ScanFunc {
	return func(ctx context.Context, req agent.ScanRequest) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{phaseCfg.Target}
		opts.ScanUUID = phaseCfg.ScanUUID
		opts.ProjectUUID = phaseCfg.ProjectUUID
		opts.ConfigPath = phaseCfg.ConfigPath
		opts.HeuristicsCheck = "none"
		opts.PassiveModules = []string{"all"}

		// Apply generated auth config from source analysis or custom instruction.
		// Use best-effort mode: AI-generated configs may be malformed, so session
		// init errors become warnings rather than aborting the scan.
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		if req.IsRescan {
			// Triage rescans: targeted dynamic-assessment only
			opts.OnlyPhase = "dynamic-assessment"
			opts.SkipIngestion = true
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
		} else {
			// Initial scan: honor the plan when it selected specific modules.
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
			if len(opts.Modules) == 0 {
				opts.Modules = []string{"all"}
			}
			// Apply user-specified phase control
			if onlyPhase != "" {
				opts.OnlyPhase = onlyPhase
			}
			if len(skipPhases) > 0 {
				opts.SkipPhases = skipPhases
			}
		}

		// Pass through verbose flag so dynamic-assessment traffic/finding lines are printed
		opts.Verbose = phaseCfg.Verbose

		// Clone settings to avoid mutating shared config
		settingsCopy := *settings
		mergeAgentExtensionDir(&settingsCopy.DynamicAssessment.Extensions, req.ExtensionDir)

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
func buildSwarmDiscoverFunc(settings *config.Settings, repo *database.Repository, phaseCfg swarmNativePhaseConfig, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		// Defensive: target derivation upstream should populate phaseCfg.Target,
		// but if it slips through empty (e.g. a record UUID that didn't resolve),
		// don't waste a spider pass on "" — spitolas rejects an empty host with
		// "target URL must have a host" and the run hard-errors.
		if strings.TrimSpace(phaseCfg.Target) == "" {
			fmt.Fprintf(os.Stderr, "%s Discovery skipped: no target URL resolved from input\n",
				terminal.WarningSymbol())
			return nil
		}
		opts := types.DefaultOptions()
		opts.Targets = []string{phaseCfg.Target}
		opts.ScanUUID = phaseCfg.ScanUUID
		opts.ProjectUUID = phaseCfg.ProjectUUID
		opts.ConfigPath = phaseCfg.ConfigPath
		opts.OnlyPhase = "discovery"
		opts.DiscoverEnabled = true
		opts.SpideringEnabled = true
		opts.HeuristicsCheck = "basic"
		opts.Silent = true
		opts.ScanConfigPrinted = true

		// Apply generated auth config for authenticated crawling
		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
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

	if result.Degraded {
		fmt.Fprintf(os.Stderr, "  %s %s warning(s)\n",
			terminal.Gray("Warnings:"),
			terminal.BoldYellow(fmt.Sprintf("%d", len(result.Warnings))))
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

// buildSyntheticCheckpoint creates a checkpoint with all phases before the target marked as completed.
// This enables --start-from to skip earlier phases without a real resume directory.
func buildSyntheticCheckpoint(startFrom string) *agent.SwarmCheckpoint {
	// Ordered swarm phases
	allPhases := []string{
		agent.SwarmPhaseNormalize,
		agent.SwarmPhaseSourceAnalysis,
		agent.SwarmPhaseCodeAudit,
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
	settings, err := guardOrRefuseFromPrompt(context.Background(), prompt, swarmDisableGuardrail)
	if err != nil {
		return err
	}

	intent, engine, repo, err := parsePromptIntent(settings, prompt)
	if err != nil {
		return err
	}
	if intent.Cleanup != nil {
		defer intent.Cleanup.Cleanup()
	}

	// Forward the verbatim prompt to the operator agent as its primary
	// instruction. See the matching block in runAutopilotFromPrompt for why
	// we drop the LLM-paraphrased app.Instruction.
	swarmInstructionPrefix = intent.Raw
	for i := range intent.Apps {
		intent.Apps[i].Instruction = ""
	}

	if swarmDryRun {
		return printIntentDryRun(intent)
	}

	// Single app: populate flags and re-enter the main flow.
	// Close the intent-parsing engine first so runAgentSwarm creates its own cleanly.
	if len(intent.Apps) == 1 {
		applyIntentToSwarmFlags(cmd, intent.Apps[0])
		return runAgentSwarm(cmd, nil)
	}

	// Multi-app: fan-out parallel runs using the already-created engine
	fmt.Fprintf(os.Stderr, "%s Parsed %d apps from prompt, running in parallel\n",
		terminal.InfoSymbol(), len(intent.Apps))
	return runMultiAppSwarm(context.Background(), cmd, engine, settings, repo, intent)
}

// applyIntentToSwarmFlags populates swarm package-level flags from an AppIntent.
func applyIntentToSwarmFlags(cmd *cobra.Command, app agent.AppIntent) {
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
	if app.Piolium != "" && swarmPiolium == "" {
		swarmPiolium = app.Piolium
		if app.Audit == "" && swarmAudit == "" {
			swarmAudit = "off"
		}
	}
	if app.Audit != "" && swarmAudit == "" {
		swarmAudit = app.Audit
	}
	if app.Diff != "" && swarmDiff == "" {
		swarmDiff = app.Diff
	}
	if len(app.Files) > 0 && len(swarmFiles) == 0 {
		swarmFiles = app.Files
	}
	if app.Browser || app.RequiresBrowser {
		swarmBrowser = true
	}
	if app.AuthRequired || app.RequiresBrowser || app.Credentials != "" || len(app.CredentialSets) > 0 {
		swarmBrowserAuthRequired = true
	}
	if app.RequiresBrowser {
		swarmRequiresBrowser = true
		swarmBrowserAuth = true
	}
	if app.Credentials != "" && swarmCredentials == "" {
		swarmCredentials = app.Credentials
	}
	if len(app.CredentialSets) > 0 && len(swarmCredentialSets) == 0 {
		swarmCredentialSets = append([]agent.IntentCredentialSet(nil), app.CredentialSets...)
	}
	if app.BrowserStartURL != "" && swarmBrowserStartURL == "" {
		swarmBrowserStartURL = app.BrowserStartURL
	}
	if len(app.FocusRoutes) > 0 && len(swarmFocusRoutes) == 0 {
		swarmFocusRoutes = append([]string(nil), app.FocusRoutes...)
	}
	if app.Intensity != "" && !cmd.Flags().Changed("intensity") {
		swarmIntensity = app.Intensity
	}
	fmt.Fprintf(os.Stderr, "%s Resolved: target=%s source=%s discover=%v\n",
		terminal.SuccessSymbol(),
		valueOrNone(swarmTarget),
		valueOrNone(terminal.ShortenHome(swarmSource)),
		swarmDiscover)
}

// runMultiAppSwarm fans out parallel swarm runs for multiple apps.
func runMultiAppSwarm(ctx context.Context, cmd *cobra.Command, engine *agent.Engine, settings *config.Settings, repo *database.Repository, intent *agent.ScanIntent) error {
	if swarmMaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, swarmMaxDuration)
		defer cancel()
	}

	return runMultiAppFanOut(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		agenticScanUUID := uuid.New().String()
		sessionDir, _ := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), agenticScanUUID)

		instruction := mergeIntentInstruction(swarmInstruction, swarmInstructionFile, app)
		instruction = prependVerbatimPrompt(instruction, swarmInstructionPrefix)
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

		phaseCfg := swarmNativePhaseConfig{
			Target:      app.Target,
			ProjectUUID: projectUUID,
			ScanUUID:    globalScanUUID,
			ConfigPath:  globalConfig,
			Verbose:     globalVerbose,
		}

		cfg := agent.SwarmConfig{
			Inputs:          inputs,
			Instruction:     instruction,
			SourcePath:      app.SourcePath,
			VulnType:        vulnType,
			Focus:           focus,
			MaxIterations:   swarmMaxIterations,
			AgentName:       swarmAgentLabel,
			ShowPrompt:      swarmShowPrompt,
			CodeAudit:       codeAudit,
			ForceExtensions: swarmForceExtensions,
			Browser:         swarmBrowser || app.Browser || app.RequiresBrowser,
			Auth:            swarmBrowserAuth || app.RequiresBrowser,
			Credentials: func() string {
				if app.Credentials != "" {
					return app.Credentials
				}
				return swarmCredentials
			}(),
			CredentialSets: func() []agent.IntentCredentialSet {
				if len(app.CredentialSets) > 0 {
					return append([]agent.IntentCredentialSet(nil), app.CredentialSets...)
				}
				return append([]agent.IntentCredentialSet(nil), swarmCredentialSets...)
			}(),
			AuthRequired: func() bool {
				return swarmBrowserAuthRequired || app.AuthRequired || app.RequiresBrowser || app.Credentials != "" || len(app.CredentialSets) > 0
			}(),
			RequiresBrowser: func() bool {
				return swarmRequiresBrowser || app.RequiresBrowser
			}(),
			BrowserStartURL: func() string {
				if app.BrowserStartURL != "" {
					return app.BrowserStartURL
				}
				return swarmBrowserStartURL
			}(),
			FocusRoutes: func() []string {
				if len(app.FocusRoutes) > 0 {
					return append([]string(nil), app.FocusRoutes...)
				}
				return append([]string(nil), swarmFocusRoutes...)
			}(),
			SkipPhases:      skipPhases,
			SessionsDir:     settings.Agent.EffectiveSessionsDir(),
			SessionDir:      sessionDir,
			AgenticScanUUID: agenticScanUUID,
			ProjectUUID:     projectUUID,
			ScanUUID:        globalScanUUID,
		}

		// Wire scan callback using per-app target (not the package-level swarmTarget)
		cfg.ScanFunc = buildMultiAppSwarmScanFunc(settings, repo, phaseCfg, swarmOnlyPhase, swarmSkipPhases, &generatedAuthConfig)

		// Same wiring as the single-app path: browser-auth output should
		// feed the discovery + scan funcs.
		cfg.BrowserAuthCallback = newBrowserAuthCallback(&generatedAuthConfig, app.Target)

		if app.Discover && app.Target != "" {
			cfg.DiscoverFunc = buildMultiAppSwarmDiscoverFunc(settings, repo, phaseCfg, &generatedAuthConfig)
		}

		swarmRunner := agent.NewSwarmRunner(engine, repo)
		_, runErr := swarmRunner.Run(ctx, cfg)
		return runErr
	})
}

// buildMultiAppSwarmScanFunc is like buildAgentSwarmScanFunc but takes an explicit
// per-run phase config instead of relying on package-level CLI globals.
// This is necessary for multi-app fan-out where each goroutine has a different target.
func buildMultiAppSwarmScanFunc(settings *config.Settings, repo *database.Repository, phaseCfg swarmNativePhaseConfig, onlyPhase string, skipPhases []string, authConfigPath *string) agent.ScanFunc {
	return func(ctx context.Context, req agent.ScanRequest) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{phaseCfg.Target}
		opts.ScanUUID = phaseCfg.ScanUUID
		opts.ProjectUUID = phaseCfg.ProjectUUID
		opts.ConfigPath = phaseCfg.ConfigPath
		opts.HeuristicsCheck = "none"
		opts.PassiveModules = []string{"all"}

		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		if req.IsRescan {
			opts.OnlyPhase = "dynamic-assessment"
			opts.SkipIngestion = true
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
		} else {
			opts.Modules = agent.ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
			if len(opts.Modules) == 0 {
				opts.Modules = []string{"all"}
			}
			if onlyPhase != "" {
				opts.OnlyPhase = onlyPhase
			}
			if len(skipPhases) > 0 {
				opts.SkipPhases = skipPhases
			}
		}

		opts.Verbose = phaseCfg.Verbose

		settingsCopy := *settings
		mergeAgentExtensionDir(&settingsCopy.DynamicAssessment.Extensions, req.ExtensionDir)

		fmt.Fprintf(os.Stderr, "%s Scanning %s with modules: %s\n",
			terminal.GrbRed(terminal.SymbolSparkle), phaseCfg.Target,
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
// per-run phase config instead of relying on package-level CLI globals.
func buildMultiAppSwarmDiscoverFunc(settings *config.Settings, repo *database.Repository, phaseCfg swarmNativePhaseConfig, authConfigPath *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if strings.TrimSpace(phaseCfg.Target) == "" {
			fmt.Fprintf(os.Stderr, "%s Discovery skipped: no target URL resolved from input\n",
				terminal.WarningSymbol())
			return nil
		}
		opts := types.DefaultOptions()
		opts.Targets = []string{phaseCfg.Target}
		opts.ScanUUID = phaseCfg.ScanUUID
		opts.ProjectUUID = phaseCfg.ProjectUUID
		opts.ConfigPath = phaseCfg.ConfigPath
		opts.HeuristicsCheck = "none"
		opts.Silent = true
		opts.ScanConfigPrinted = true

		if authConfigPath != nil && *authConfigPath != "" {
			opts.AuthFiles = []string{*authConfigPath}
			opts.AuthBestEffort = true
		}

		fmt.Fprintf(os.Stderr, "%s Discovery+spidering for %s (crawl, JS analysis, external harvesting)\n",
			terminal.GrbRed(terminal.SymbolSparkle), phaseCfg.Target)

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
