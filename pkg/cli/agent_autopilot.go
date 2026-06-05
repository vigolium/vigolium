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
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/spitolas"
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
	autopilotSkills           []string
	autopilotSkillTags        []string
	autopilotNoSkillFilter    bool
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
	autopilotAudit            string // canonical audit control: "" | "lite" | "balanced" | "deep" | "off"
	autopilotPiolium          string // piolium audit control: "" (auto/off) | "lite"|"balanced"|"deep"|... | "off"
	autopilotDiff             string
	autopilotLastCommits      int
	autopilotIntensity        string
	autopilotNoPrescan        bool
	autopilotTriage           bool
	autopilotNoPreflight      bool
	autopilotNoPostHaltVerify bool
	autopilotPostHaltGap      int
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
	autopilotHeaded           bool

	// autopilotInstructionPrefix holds the verbatim natural-language prompt
	// when autopilot was invoked with a positional `<prompt>` argument. It is
	// prepended in front of any --instruction / --instruction-file content so
	// nuanced guidance the user typed (e.g. exploitation hints, origin
	// constraints) reaches the operator agent unaltered. Structured fields
	// (target/source/focus/audit/intensity) are still extracted by the LLM
	// intent parser; only the instruction channel is replaced with verbatim.
	autopilotInstructionPrefix string
)

var agentAutopilotCmd = &cobra.Command{
	Use:   "autopilot [prompt]",
	Short: "Agentic scan: autonomous AI-driven vulnerability scanning",
	Long: `Autonomous AI scan: the operator runs vigolium CLI commands
(scan-url, finding, traffic, …) to discover, scan, and triage on its own.

Examples (natural-language prompt as positional arg):
  vigolium agent autopilot "scan VAmPI at localhost:3005 with source ~/src/VAmPI"
  vigolium agent autopilot "XSS on https://target/page — popup origin must be target"
  vigolium agent autopilot --plan-file ginandjuice-plan.md
  vigolium agent autopilot -t https://target --no-prescan   # skip native pre-scan, hand the operator a cold target

The prompt is forwarded verbatim to the operator (hints, caveats, scope rules
all reach it word-for-word) and parsed for target/source/focus. --instruction
appends extra guidance. --dry-run previews what the parser extracted.

Inputs (--input, auto-detected; also reads stdin when piped):
  URL · curl command · raw HTTP · Burp XML · base64 raw HTTP

--plan-file: one file mixing prose + raw HTTP request(s) split on "---" or
fenced ` + "```http```" + ` blocks. First request is the live seed; rest fold into
context. Mutually exclusive with --input/--instruction/--instruction-file.

--source enables whitebox: vigolium-audit prepares a context bundle + plan
before the operator launches. Disable with --audit=off.

Intensity presets (--intensity), explicit flags override:
  quick     — 30 cmds, 1h,  lite  audit + pre-scan
  balanced  — 100 cmds, 6h,  balanced audit + pre-scan  (default)
  deep      — 300 cmds, 12h, deep  audit + pre-scan

Pre-scan runs a full native scan (discovery + spidering + dynamic-assessment)
to seed http_records before the operator starts (target-only runs; skip with
--no-prescan).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgentAutopilot,
}

func init() {
	agentCmd.AddCommand(agentAutopilotCmd)
	f := agentAutopilotCmd.Flags()

	f.StringVarP(&autopilotTarget, "target", "t", "", "Target URL (derived from --input if not set)")
	f.StringVar(&autopilotInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.BoolVar(&globalDBIsolate, "db-isolate", false, dbIsolateAgentFlagUsage)
	f.StringVar(&autopilotRecordUUID, "record-uuid", "", "Use an HTTP record from the database as the seed input (looked up by UUID)")
	f.StringVar(&autopilotOliumProvider, "provider", "", "Olium provider override: openai-codex-oauth | openai-api-key | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible (falls back to agent.olium.provider config)")
	f.StringVar(&autopilotOliumModel, "model", "", "Olium model id override (falls back to agent.olium.model)")
	f.StringVar(&autopilotSystemPrompt, "system-prompt", "", "Replace the built-in autopilot system prompt with this value (full replace; browser section is not auto-appended)")
	f.StringVar(&autopilotSystemPromptFile, "system-prompt-file", "", "Path to a file whose contents replace the built-in autopilot system prompt (takes precedence over --system-prompt)")
	f.StringVar(&autopilotOliumOAuthCred, "oauth-cred", "", "Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS)")
	f.StringVar(&autopilotOliumOAuthToken, "oauth-token", "", "Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	f.StringVar(&autopilotOliumLLMAPIKey, "llm-api-key", "", "Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var)")
	f.StringVar(&autopilotSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --source)")
	f.StringVar(&autopilotFocus, "focus", "", "Focus area hint (e.g. 'API injection', 'auth bypass')")
	f.StringSliceVar(&autopilotSkills, "skill", nil, "Force-load these skills by name, bypassing the pre-flight selection (repeatable or comma-separated)")
	f.StringSliceVar(&autopilotSkillTags, "skill-tag", nil, "Force-load every skill carrying one of these tags (e.g. xss,idor)")
	f.BoolVar(&autopilotNoSkillFilter, "no-skill-filter", false, "Load the full skill set; skip the pre-flight skill selection")
	f.DurationVar(&autopilotMaxDuration, "max-duration", 6*time.Hour, "Maximum wall-clock duration for the autopilot session (e.g. 1h, 6h)")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.BoolVar(&autopilotShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.StringVar(&autopilotInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	f.StringVar(&autopilotInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.StringVar(&autopilotPlanFile, "plan-file", "", "Path to a plan file mixing free-text guidance and raw HTTP request(s). Owns the instruction + seed input; cannot be combined with --input/--instruction/--instruction-file")
	f.BoolVar(&autopilotBrowser, "browser", false, "Enable agent-browser for browser-based interactions")
	f.BoolVar(&autopilotHeaded, "headed", false, "Show the browser window: applies to the native pre-scan spidering when the pre-scan runs (i.e. not with --no-prescan or --source); additionally applies to in-process probes (browser_probe, web_fetch mode=browser) and agent-browser subprocesses when --browser is enabled. Sets VIGOLIUM_BROWSER_HEADED=1 for the duration of the run.")
	f.StringVar(&autopilotCredentials, "credentials", "", "Credentials for auth preflight (e.g. 'admin/admin123, compare user/user123')")
	f.BoolVar(&autopilotAuthRequired, "auth-required", false, "Require auth/session preparation before the autonomous operator starts")
	f.BoolVar(&autopilotRequiresBrowser, "requires-browser", false, "Require browser-assisted auth/setup instead of HTTP-only preflight")
	f.StringVar(&autopilotBrowserStartURL, "browser-start-url", "", "Explicit browser/login start URL for auth preflight")
	f.StringSliceVar(&autopilotFocusRoutes, "focus-routes", nil, "Protected or browser-focused routes to prioritize after auth")
	f.StringVar(&autopilotAudit, "audit", "lite", "vigolium-audit mode: lite (3-phase), balanced (9-phase), deep (12-phase), mock (sample output), or off (disable). Default: lite when --source is set")
	f.StringVar(&autopilotPiolium, "piolium", "", "Piolium audit mode: lite, balanced, deep, longshot, etc. Default: empty triggers auto-pick (piolium when pi is installed, else audit). Set explicitly to force piolium; set --audit=off alongside to disable audit")
	f.StringVar(&autopilotDiff, "diff", "", "Focus on changed code: PR URL (github.com/.../pull/123), git ref range (main...branch), or HEAD~N")
	f.IntVar(&autopilotLastCommits, "last-commits", 0, "Focus on last N commits (shorthand for --diff HEAD~N)")
	f.StringVar(&autopilotIntensity, "intensity", "balanced", "Scan intensity preset: quick, balanced, or deep")
	f.BoolVar(&autopilotNoPrescan, "no-prescan", false, "Skip the native pre-scan that seeds http_records before the operator agent (target-only runs; no-op when --source is set)")
	f.BoolVar(&autopilotTriage, "triage", false, "After the scan completes, run an AI triage pass over the findings (confirm real issues vs false positives, written back to finding status)")
	f.BoolVar(&autopilotNoPreflight, "no-preflight-discovery", false, "Skip the pre-flight discovery + OpenAPI/Swagger ingestion pass that seeds http_records before the operator agent starts")
	f.BoolVar(&autopilotNoPostHaltVerify, "no-post-halt-verify", false, "Skip the post-halt coverage verification re-entry (operator halts → coverage probe → re-prompt agent when new routes turn up)")
	f.IntVar(&autopilotPostHaltGap, "post-halt-gap-threshold", 0, "Minimum new (method, URL) routes the post-halt probe must turn up before the agent is re-entered. 0 = built-in default (5)")

	f.BoolVar(&autopilotUploadResults, "upload-results", false, "Upload scan results to cloud storage after completion (requires storage config)")
	f.BoolVar(&autopilotDisableGuardrail, "disable-guardrail", false, "Skip the prompt-safety classifier on the natural-language prompt (use only when refusing a known-good prompt)")
	f.BoolVarP(&autopilotVerbose, "verbose", "v", false, "Show a per-tool head/tail preview of each tool result alongside the standard one-liner")
}

func runAgentAutopilot(cmd *cobra.Command, args []string) (err error) {
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
		// ResolveAutopilotIntensity still takes the legacy (mode, noAudit) pair —
		// translate, resolve, then translate back.
		auditChanged := cmd.Flags().Changed("audit")
		auditModeLocal := autopilotAudit
		noAudit := autopilotAudit == "off"
		if noAudit {
			auditModeLocal = ""
		}
		changed := map[string]bool{
			"timeout":    cmd.Flags().Changed("max-duration"),
			"audit-mode": auditChanged,
			"no-audit":   auditChanged && noAudit,
			"browser":    cmd.Flags().Changed("browser"),
			"no-prescan": cmd.Flags().Changed("no-prescan"),
		}
		intensityResult := agent.ResolveAutopilotIntensity(intensity, agent.AutopilotIntensityPreset{
			MaxCommands:     autopilotMaxCommands,
			Timeout:         autopilotMaxDuration,
			AuditDriverMode: auditModeLocal,
			Browser:         autopilotBrowser,
			NoPrescan:       autopilotNoPrescan,
		}, changed)
		autopilotMaxCommands = intensityResult.MaxCommands
		autopilotMaxDuration = intensityResult.Timeout
		if !noAudit {
			autopilotAudit = intensityResult.AuditDriverMode
		}
		autopilotBrowser = intensityResult.Browser
		autopilotNoPrescan = intensityResult.NoPrescan

		// Audit-harness auto-pick: when neither flag is explicit, prefer
		// piolium if pi+piolium are installed; otherwise audit's existing
		// lite-default applies. Explicit --piolium turns audit off so the
		// two harnesses don't double-run.
		pioliumChanged := cmd.Flags().Changed("piolium")
		switch {
		case !auditChanged && !pioliumChanged && piolium.IsAvailable():
			autopilotPiolium = autopilotAudit
			autopilotAudit = "off"
		case pioliumChanged && !auditChanged:
			autopilotAudit = "off"
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

	if autopilotHeaded {
		_ = os.Setenv(spitolas.EnvBrowserHeaded, "1")
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

	// --db-isolate: run into a private temp DB and merge into the real --db (or
	// default DB) at the end, so parallel autopilot runs can share one --db
	// without contending on a single SQLite writer. Repoints globalDB at the
	// scratch so the getDB() call below opens it; the merge defer runs after the
	// run completes (all writes committed) and reads the scratch via ATTACH.
	finish, dErr := dbIsolateBegin(settings, globalSilent)
	if dErr != nil {
		return dErr
	}
	defer func() { err = finish(err) }()

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
	instruction = prependVerbatimPrompt(instruction, autopilotInstructionPrefix)

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
		// audit/swarm/scan behavior.
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

	// Forward the verbatim prompt to the operator agent as its primary
	// instruction. The LLM extractor populated app.Instruction with a
	// paraphrase that may drop nuance (e.g. exploitation hints, origin
	// constraints) — clear it so only the verbatim text reaches the agent.
	autopilotInstructionPrefix = intent.Raw
	for i := range intent.Apps {
		intent.Apps[i].Instruction = ""
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
		if app.Audit == "" {
			autopilotAudit = "off"
		}
	}
	if app.Audit != "" {
		autopilotAudit = app.Audit
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
		clicommon.ValueOrNone(autopilotTarget),
		clicommon.ValueOrNone(terminal.ShortenHome(autopilotSource)))
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
			clicommon.ValueOrNone(app.Target),
			clicommon.ValueOrNone(terminal.ShortenHome(app.SourcePath)))

		instruction := mergeIntentInstruction(autopilotInstruction, autopilotInstructionFile, app)
		instruction = prependVerbatimPrompt(instruction, autopilotInstructionPrefix)

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
