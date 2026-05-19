package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// agent autopilot flags
var (
	autopilotTarget           string
	autopilotInput            string
	autopilotRecordUUID       string
	autopilotSource           string
	autopilotFiles            []string
	autopilotFocus            string
	autopilotMaxDuration      time.Duration
	autopilotDryRun           bool
	autopilotShowPrompt       bool
	autopilotMaxCommands      int
	autopilotInstruction      string
	autopilotInstructionFile  string
	autopilotPlanFile         string
	autopilotBrowser          bool
	autopilotCredentials      string
	autopilotAuthRequired     bool
	autopilotRequiresBrowser  bool
	autopilotBrowserStartURL  string
	autopilotFocusRoutes      []string
	autopilotArchon           string // canonical archon control: "" | "lite" | "balanced" | "deep" | "off"
	autopilotPiolium          string // piolium audit control: "" (auto/off) | "lite"|"balanced"|"deep"|... | "off"
	autopilotDiff             string
	autopilotLastCommits      int
	autopilotIntensity        string
	autopilotNoPrescan        bool
	autopilotTriage           bool
	autopilotUploadResults    bool
	autopilotVerbose          bool
	autopilotOliumProvider    string
	autopilotOliumModel       string
	autopilotSystemPrompt     string
	autopilotSystemPromptFile string
	autopilotOliumOAuthCred   string
	autopilotOliumOAuthToken  string
	autopilotOliumLLMAPIKey   string
	autopilotDisableGuardrail bool
)

var agentAutopilotCmd = &cobra.Command{
	Use:   "autopilot [prompt]",
	Short: "Agentic scan: autonomous AI-driven vulnerability scanning",
	Long: `Launch an agentic scan that autonomously discovers, scans, and triages
vulnerabilities using vigolium CLI commands.

The agent runs commands like scan-url, finding, traffic via its terminal
capabilities to discover endpoints, scan for vulnerabilities, review
results, and iterate until done.

When --source is provided, archon-audit runs before the autonomous agent.
Autopilot prepares the source audit into a stable context bundle and native
plan, then launches the operator against that prepared context.
Use --archon=off to disable this behavior.

Supports natural language prompts as a positional argument:
  vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
  vigolium agent autopilot "scan all source code from ~/src/crAPI, ~/src/DVWA"

The prompt is parsed by an AI to extract target URLs, source paths, and focus areas.
Use --dry-run to preview what the parser extracts without executing.

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)

When input is piped via stdin, it is automatically read (no --input needed).
The target URL is extracted from the input when --target is not provided.

Plan file (--plan-file): a single file mixing free-text guidance and raw
HTTP request(s) — exactly what you'd paste. Prose before the first request
becomes the instruction; the request region (split on lines that are exactly
"---", or fenced ` + "```http```" + ` blocks) supplies the seed request(s). The
first request is the live seed; any extras are folded into the instruction as
context. --plan-file cannot be combined with --input/--instruction/
--instruction-file (it owns both):
  vigolium agent autopilot --plan-file ginandjuice-plan.md

Intensity presets (--intensity) bundle multiple settings into a single flag:
  quick     — Fast CI/PR scans: 30 commands, 1h timeout, lite archon, lite pre-scan
  balanced  — Standard assessment (default): 100 commands, 6h timeout, balanced archon, balanced pre-scan
  deep      — Thorough pentest: 300 commands, 12h timeout, deep archon, deep pre-scan

Browser-assisted probing is enabled at every intensity. Pre-scan runs a native
discovery + dynamic-assessment pass against --target before the operator agent
starts so it has real http_records to reason about; pass --no-prescan to skip.
The pre-scan only fires in target-only runs — when --source is set, archon (or
piolium) provides the structured pre-context instead.

Explicit flags always override intensity presets.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgentAutopilot,
}

func init() {
	agentCmd.AddCommand(agentAutopilotCmd)
	f := agentAutopilotCmd.Flags()

	f.StringVarP(&autopilotTarget, "target", "t", "", "Target URL (derived from --input if not set)")
	f.StringVar(&autopilotInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&autopilotRecordUUID, "record-uuid", "", "Use an HTTP record from the database as the seed input (looked up by UUID)")
	f.StringVar(&autopilotOliumProvider, "provider", "", "Olium provider override: openai-codex-oauth | openai-api-key | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible (falls back to agent.olium.provider config)")
	f.StringVar(&autopilotOliumModel, "model", "", "Olium model id override (olium backend only; falls back to agent.olium.model)")
	f.StringVar(&autopilotSystemPrompt, "system-prompt", "", "Replace the built-in autopilot system prompt with this value (full replace; browser section is not auto-appended)")
	f.StringVar(&autopilotSystemPromptFile, "system-prompt-file", "", "Path to a file whose contents replace the built-in autopilot system prompt (takes precedence over --system-prompt)")
	f.StringVar(&autopilotOliumOAuthCred, "oauth-cred", "", "Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS)")
	f.StringVar(&autopilotOliumOAuthToken, "oauth-token", "", "Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	f.StringVar(&autopilotOliumLLMAPIKey, "llm-api-key", "", "Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var)")
	f.StringVar(&autopilotSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --source)")
	f.StringVar(&autopilotFocus, "focus", "", "Focus area hint (e.g. 'API injection', 'auth bypass')")
	f.DurationVar(&autopilotMaxDuration, "max-duration", 6*time.Hour, "Maximum wall-clock duration for the autopilot session (e.g. 1h, 6h)")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.BoolVar(&autopilotShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.StringVar(&autopilotInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	f.StringVar(&autopilotInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.StringVar(&autopilotPlanFile, "plan-file", "", "Path to a plan file mixing free-text guidance and raw HTTP request(s). Owns the instruction + seed input; cannot be combined with --input/--instruction/--instruction-file")
	f.BoolVar(&autopilotBrowser, "browser", false, "Enable agent-browser for browser-based interactions")
	f.StringVar(&autopilotCredentials, "credentials", "", "Credentials for auth preflight (e.g. 'admin/admin123, compare user/user123')")
	f.BoolVar(&autopilotAuthRequired, "auth-required", false, "Require auth/session preparation before the autonomous operator starts")
	f.BoolVar(&autopilotRequiresBrowser, "requires-browser", false, "Require browser-assisted auth/setup instead of HTTP-only preflight")
	f.StringVar(&autopilotBrowserStartURL, "browser-start-url", "", "Explicit browser/login start URL for auth preflight")
	f.StringSliceVar(&autopilotFocusRoutes, "focus-routes", nil, "Protected or browser-focused routes to prioritize after auth")
	f.StringVar(&autopilotArchon, "archon", "lite", "Archon audit mode: lite (3-phase), balanced (6-phase), deep (10-phase), mock (sample output), or off (disable). Default: lite when --source is set")
	f.StringVar(&autopilotPiolium, "piolium", "", "Piolium audit mode: lite, balanced, deep, longshot, etc. Default: empty triggers auto-pick (piolium when pi is installed, else archon). Set explicitly to force piolium; set --archon=off alongside to disable archon")
	f.StringVar(&autopilotDiff, "diff", "", "Focus on changed code: PR URL (github.com/.../pull/123), git ref range (main...branch), or HEAD~N")
	f.IntVar(&autopilotLastCommits, "last-commits", 0, "Focus on last N commits (shorthand for --diff HEAD~N)")
	f.StringVar(&autopilotIntensity, "intensity", "balanced", "Scan intensity preset: quick, balanced, or deep")
	f.BoolVar(&autopilotNoPrescan, "no-prescan", false, "Skip the native pre-scan that seeds http_records before the operator agent (target-only runs; no-op when --source is set)")
	f.BoolVar(&autopilotTriage, "triage", false, "After the scan completes, run an AI triage pass over the findings (confirm real issues vs false positives, written back to finding status)")

	f.BoolVar(&autopilotUploadResults, "upload-results", false, "Upload scan results to cloud storage after completion (requires storage config)")
	f.BoolVar(&autopilotDisableGuardrail, "disable-guardrail", false, "Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt)")
	f.BoolVarP(&autopilotVerbose, "verbose", "v", false, "Show a per-tool head/tail preview of each tool result alongside the standard one-liner")
}

func runAgentAutopilot(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Natural language prompt: positional arg takes precedence when no explicit flags are set
	hasExplicitFlags := autopilotTarget != "" || autopilotInput != "" || autopilotRecordUUID != "" || autopilotSource != "" || autopilotPlanFile != ""
	if len(args) > 0 && !hasExplicitFlags {
		return runAutopilotFromPrompt(args[0])
	}

	intensity, err := agent.ValidateIntensity(autopilotIntensity)
	if err != nil {
		return err
	}
	if cmd != nil {
		// ResolveAutopilotIntensity still takes the legacy (mode, noArchon) pair —
		// translate, resolve, then translate back.
		archonChanged := cmd.Flags().Changed("archon")
		archonMode := autopilotArchon
		noArchon := autopilotArchon == "off"
		if noArchon {
			archonMode = ""
		}
		changed := map[string]bool{
			"timeout":     cmd.Flags().Changed("max-duration"),
			"archon-mode": archonChanged,
			"no-archon":   archonChanged && noArchon,
			"browser":     cmd.Flags().Changed("browser"),
			"no-prescan":  cmd.Flags().Changed("no-prescan"),
		}
		intensityResult := agent.ResolveAutopilotIntensity(intensity, agent.AutopilotIntensityPreset{
			MaxCommands: autopilotMaxCommands,
			Timeout:     autopilotMaxDuration,
			ArchonMode:  archonMode,
			Browser:     autopilotBrowser,
			NoPrescan:   autopilotNoPrescan,
		}, changed)
		autopilotMaxCommands = intensityResult.MaxCommands
		autopilotMaxDuration = intensityResult.Timeout
		if !noArchon {
			autopilotArchon = intensityResult.ArchonMode
		}
		autopilotBrowser = intensityResult.Browser
		autopilotNoPrescan = intensityResult.NoPrescan

		// Audit-harness auto-pick: when neither flag is explicit, prefer
		// piolium if pi+piolium are installed; otherwise archon's existing
		// lite-default applies. Explicit --piolium turns archon off so the
		// two harnesses don't double-run.
		pioliumChanged := cmd.Flags().Changed("piolium")
		switch {
		case !archonChanged && !pioliumChanged && piolium.IsAvailable():
			autopilotPiolium = autopilotArchon
			autopilotArchon = "off"
		case pioliumChanged && !archonChanged:
			autopilotArchon = "off"
		}
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}
	// Layer the global --ext / --ext-dir flags so user-supplied extensions
	// run alongside anything the autopilot produces.
	applyGlobalExtFlagsToSettings(settings)

	// --browser flag overrides config
	if autopilotBrowser {
		enabled := true
		settings.Agent.Browser.Enable = &enabled
	}

	// Apply olium provider override flags onto settings so the pipeline
	// runner (which reads settings.Agent.Olium directly) sees them too.
	// runAutopilotOlium also re-applies via firstNonEmptyString for the
	// direct path; this just keeps the two code paths in sync.
	if autopilotOliumProvider != "" {
		settings.Agent.Olium.Provider = autopilotOliumProvider
	}
	if autopilotOliumModel != "" {
		settings.Agent.Olium.Model = autopilotOliumModel
	}
	if autopilotOliumOAuthCred != "" {
		settings.Agent.Olium.OAuthCredPath = autopilotOliumOAuthCred
	}
	if autopilotOliumOAuthToken != "" {
		settings.Agent.Olium.OAuthToken = autopilotOliumOAuthToken
	}
	if autopilotOliumLLMAPIKey != "" {
		settings.Agent.Olium.LLMAPIKey = autopilotOliumLLMAPIKey
	}

	// Open DB for context enrichment. The repo is also needed during input
	// resolution so --input <record-uuid> and the --record-uuid flag can
	// look up records from the database.
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	// Resolve --plan-file into --instruction/--input before the generic
	// resolvers run. Autopilot is single-seed: the first request block is the
	// live seed, the rest become labelled context in the instruction.
	if autopilotPlanFile != "" {
		// resolvePlanFile owns the --input/--instruction/--instruction-file
		// conflicts; --record-uuid is checked here because it's autopilot-only
		// (it resolves to a single seed, which the plan file already supplies).
		// Swarm has no equivalent: its --record-uuid is multi-valued and just
		// adds more seeds alongside the plan's, so combining is allowed there.
		if autopilotRecordUUID != "" {
			return fmt.Errorf("--plan-file cannot be combined with --record-uuid")
		}
		planInstruction, planRequests, perr := resolvePlanFile(
			autopilotPlanFile, autopilotInput, autopilotInstruction, autopilotInstructionFile)
		if perr != nil {
			return perr
		}
		autopilotInstruction = planInstruction
		if len(planRequests) > 0 {
			autopilotInput = planRequests[0]
			if len(planRequests) > 1 {
				autopilotInstruction = appendExtraRequests(autopilotInstruction, planRequests[1:])
			}
		}
	}

	// Resolve --record-uuid (single) into --input/--target before the generic
	// input resolver runs. A bare UUID would also work via --input, but a
	// dedicated flag makes intent obvious in scripts and shell history.
	if autopilotRecordUUID != "" {
		if repo == nil {
			return fmt.Errorf("--record-uuid requires a database connection")
		}
		if autopilotInput != "" || autopilotTarget != "" {
			return fmt.Errorf("--record-uuid cannot be combined with --input or --target")
		}
		autopilotInput = strings.TrimSpace(autopilotRecordUUID)
	}

	// Resolve input and target (repo plumbed through so record-UUID lookups work)
	resolved, err := resolveInputAndTarget(autopilotTarget, autopilotInput, repo)
	if err != nil {
		return err
	}
	autopilotTarget = resolved.Target

	if autopilotTarget == "" && autopilotSource == "" {
		return fmt.Errorf("target is required: use --target, --input, --record-uuid, --source, or pipe via stdin\n\nOr use a natural language prompt:\n  vigolium agent autopilot \"scan source at ~/src/app on localhost:3005\"")
	}

	instruction, err := resolveInstruction(autopilotInstruction, autopilotInstructionFile)
	if err != nil {
		return err
	}

	// Auto-cleanup:
	//   - stale run.pid files from prior crashed olium runs (and, in the
	//     rare fork case, kill any still-alive orphan process group)
	//   - stale /tmp/vigolium-swarm-ext-* temp dirs
	//   - session directories older than 48h
	// The olium autopilot runs in-process, so "orphan process" is almost
	// always just a dead PID file lingering from a SIGKILL'd run.
	sessionsDir := settings.Agent.EffectiveSessionsDir()
	if n := agent.CleanupOrphanedProcesses(sessionsDir); n > 0 {
		zap.L().Debug("Cleared stale autopilot pid files", zap.Int("count", n))
	}
	agent.CleanupStaleTempDirs()
	if n, err := agent.CleanupSessionDirs(sessionsDir, 48*time.Hour); err == nil && n > 0 {
		zap.L().Debug("Cleaned up stale session directories", zap.Int("count", n))
	}

	if storage.IsGCSURI(autopilotSource) {
		// Pass the active project so --project-uuid (or --project-name) can
		// override the project component parsed from the gs:// URI, matching
		// archon/swarm/scan behavior.
		projectUUID, _ := resolveProjectUUID()
		extractedPath, cleanup, gcsErr := storage.ResolveGCSSource(&settings.Storage, autopilotSource, projectUUID)
		if gcsErr != nil {
			return fmt.Errorf("failed to resolve gs:// source: %w", gcsErr)
		}
		defer cleanup()
		autopilotSource = extractedPath
	}

	// Resolve source (git URL, archive, local path) and diff context so the
	// olium autopilot gets a local path it can read.
	if autopilotSource != "" || autopilotDiff != "" || autopilotLastCommits > 0 {
		var err error
		autopilotSource, autopilotFiles, _, err = agent.ResolveSourceAndDiff(
			autopilotSource, autopilotDiff, autopilotLastCommits, autopilotFiles, "")
		if err != nil {
			return err
		}
	}

	return runAutopilotOlium(settings, repo, instruction)
}

// runAutopilotFromPrompt parses a natural language prompt and runs autopilot for each extracted app.
func runAutopilotFromPrompt(prompt string) error {
	settings, err := guardOrRefuseFromPrompt(context.Background(), prompt, autopilotDisableGuardrail)
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

	if autopilotDryRun {
		return printIntentDryRun(intent)
	}

	// Single app: populate flags and re-enter the main flow.
	// Close the intent-parsing engine first so runAgentAutopilot creates its own cleanly.
	if len(intent.Apps) == 1 {
		applyIntentToAutopilotFlags(intent.Apps[0])
		return runAgentAutopilot(nil, nil)
	}

	// Multi-app: fan-out parallel runs using the already-created engine
	fmt.Fprintf(os.Stderr, "%s Parsed %d apps from prompt, running in parallel\n",
		terminal.InfoSymbol(), len(intent.Apps))
	return runMultiAppAutopilot(context.Background(), engine, settings, repo, intent)
}

// applyIntentToAutopilotFlags populates autopilot package-level flags from an AppIntent.
func applyIntentToAutopilotFlags(app agent.AppIntent) {
	autopilotTarget = app.Target
	autopilotSource = app.SourcePath
	if app.Focus != "" && autopilotFocus == "" {
		autopilotFocus = app.Focus
	}
	if app.Instruction != "" && autopilotInstruction == "" {
		autopilotInstruction = app.Instruction
	}
	if app.Piolium != "" {
		autopilotPiolium = app.Piolium
		if app.Archon == "" {
			autopilotArchon = "off"
		}
	}
	if app.Archon != "" {
		autopilotArchon = app.Archon
	}
	if app.Diff != "" && autopilotDiff == "" {
		autopilotDiff = app.Diff
	}
	if len(app.Files) > 0 && len(autopilotFiles) == 0 {
		autopilotFiles = app.Files
	}
	if app.Browser {
		autopilotBrowser = true
	}
	if app.Credentials != "" && autopilotCredentials == "" {
		autopilotCredentials = app.Credentials
	}
	if app.AuthRequired {
		autopilotAuthRequired = true
	}
	if app.RequiresBrowser {
		autopilotRequiresBrowser = true
	}
	if app.BrowserStartURL != "" && autopilotBrowserStartURL == "" {
		autopilotBrowserStartURL = app.BrowserStartURL
	}
	if len(app.FocusRoutes) > 0 && len(autopilotFocusRoutes) == 0 {
		autopilotFocusRoutes = append([]string(nil), app.FocusRoutes...)
	}
	if app.MaxCommands > 0 {
		autopilotMaxCommands = app.MaxCommands
	}
	if app.Timeout != "" {
		if d, err := time.ParseDuration(app.Timeout); err == nil {
			autopilotMaxDuration = d
		}
	}
	if app.Intensity != "" && autopilotIntensity == "balanced" {
		autopilotIntensity = app.Intensity
	}
	fmt.Fprintf(os.Stderr, "%s Resolved: target=%s source=%s\n",
		terminal.SuccessSymbol(),
		valueOrNone(autopilotTarget),
		valueOrNone(terminal.ShortenHome(autopilotSource)))
}

// runMultiAppAutopilot fans out sequential autopilot runs for multiple apps.
// Each app temporarily overrides the package-level flags and re-enters
// runAutopilotOlium, so every app gets the same olium-backed treatment as
// a single-app invocation.
func runMultiAppAutopilot(ctx context.Context, _ *agent.Engine, settings *config.Settings, repo *database.Repository, intent *agent.ScanIntent) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if autopilotMaxDuration > 0 {
		ctx, cancel = context.WithTimeout(ctx, autopilotMaxDuration)
		defer cancel()
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.L().Info("Signal received, shutting down multi-app autopilot")
		cancel()
	}()

	return runMultiAppFanOut(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		fmt.Fprintf(os.Stderr, "%s [%d/%d] Starting autopilot: target=%s source=%s\n",
			terminal.InfoSymbol(), idx+1, len(intent.Apps),
			valueOrNone(app.Target),
			valueOrNone(terminal.ShortenHome(app.SourcePath)))

		instruction := mergeIntentInstruction(autopilotInstruction, autopilotInstructionFile, app)

		// Snapshot globals, apply per-app overrides, then restore on exit.
		savedTarget := autopilotTarget
		savedSource := autopilotSource
		savedFocus := autopilotFocus
		savedMaxCmds := autopilotMaxCommands
		savedFiles := autopilotFiles
		defer func() {
			autopilotTarget = savedTarget
			autopilotSource = savedSource
			autopilotFocus = savedFocus
			autopilotMaxCommands = savedMaxCmds
			autopilotFiles = savedFiles
		}()

		autopilotTarget = app.Target
		autopilotSource = app.SourcePath
		if app.Focus != "" {
			autopilotFocus = app.Focus
		}
		if app.MaxCommands > 0 {
			autopilotMaxCommands = app.MaxCommands
		}
		if len(app.Files) > 0 {
			autopilotFiles = app.Files
		}

		return runAutopilotOlium(settings, repo, instruction)
	})
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// pinnedOrNewUUID returns the caller-pinned UUID if non-empty, otherwise a
// freshly minted v4. Used by agent CLI subcommands to honor --scan-uuid for
// cross-node sync without minting (and discarding) a UUID on every call.
func pinnedOrNewUUID(pinned string) string {
	if pinned != "" {
		return pinned
	}
	return uuid.New().String()
}
