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
	"github.com/vigolium/vigolium/pkg/burpbridge"
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
	autopilotTarget        string
	autopilotInput         string
	autopilotRecordUUID    string
	autopilotBurpBridgeURL string
	autopilotPriorContext  string
	autopilotSource        string
	autopilotFiles         []string
	autopilotPrompt        string // --prompt: free-text task guidance (same slot as the positional [prompt])
	autopilotFocus         string // internal: populated by the NL intent parser (no --focus flag)
	autopilotSkills        []string
	autopilotSkillTags     []string
	autopilotNoSkillFilter bool
	autopilotMaxDuration   time.Duration
	autopilotDryRun        bool
	autopilotShowPrompt    bool
	autopilotMaxCommands   int
	autopilotInstruction   string // internal: populated by --plan-file and the NL intent parser (no --instruction flag)
	autopilotPlanFile      string
	// Auth/browser signals below have no CLI flags — the browser is always
	// available for autopilot, and credentials/auth intent are extracted from
	// the prompt (NL path via applyIntentToAutopilotFlags, explicit path via
	// extractPromptAuthIntent).
	autopilotCredentials            string
	autopilotAuthRequired           bool
	autopilotRequiresBrowser        bool
	autopilotBrowserStartURL        string
	autopilotFocusRoutes            []string
	autopilotAudit                  string // canonical audit control: "" | "lite" | "balanced" | "deep" | "off"
	autopilotPiolium                string // piolium audit control: "" (auto/off) | "lite"|"balanced"|"deep"|... | "off"
	autopilotDiff                   string
	autopilotLastCommits            int
	autopilotIntensity              string
	autopilotNoPrescan              bool
	autopilotTriage                 bool
	autopilotNoPreflight            bool
	autopilotNoPostHaltVerify       bool
	autopilotPostHaltGap            int
	autopilotUploadResults          bool
	autopilotVerbose                bool
	autopilotOliumProvider          string
	autopilotOliumModel             string
	autopilotSystemPrompt           string
	autopilotSystemPromptFile       string
	autopilotOliumOAuthCred         string
	autopilotOliumOAuthToken        string
	autopilotOliumLLMAPIKey         string
	autopilotDisableGuardrail       bool
	autopilotHeaded                 bool
	autopilotResume                 string
	autopilotSessionDir             string
	autopilotTranscript             string
	autopilotKnowledgeBase          string
	autopilotKnowledgeBaseRaw       bool
	autopilotKnowledgeBaseNoTraffic bool

	// autopilotInstructionPrefix holds the verbatim task-guidance prompt when
	// autopilot was invoked with a positional `<prompt>` argument or --prompt. It
	// is prepended in front of any --plan-file / intent-parsed instruction so
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

Task guidance comes from the positional [prompt] or --prompt (same slot). It is
forwarded verbatim to the operator (hints, caveats, scope rules all reach it
word-for-word) and parsed for target/source/focus. --dry-run previews what the
parser extracted.

Inputs (--input, auto-detected; also reads stdin when piped):
  URL · curl command · raw HTTP · Burp XML · base64 raw HTTP

--burp-bridge-url http://127.0.0.1:9009 pulls live Burp Proxy history into the
project DB before the run, so the operator mines that traffic (and prior
findings) instead of only what a fresh scan produces.

--plan-file: one file mixing prose + raw HTTP request(s) split on "---" or
fenced ` + "```http```" + ` blocks. First request is the live seed; rest fold into
context. Mutually exclusive with --input or a prompt (--prompt / positional).

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
	f.StringVarP(&autopilotBurpBridgeURL, "burp-bridge-url", "B", burpbridge.URLFromEnvironment(), "Pull live Burp Proxy history into the project DB before the run (e.g. http://127.0.0.1:9009), so the pre-scan and operator can mine it alongside prior traffic. Also honors $VIGOLIUM_BURP_BRIDGE_URL")
	f.StringVar(&autopilotPriorContext, "prior-context", "auto", "Front-load a bounded summary of the traffic + findings already in the project DB so the operator mines them instead of starting from scratch: auto (default; the bounded table when prior data exists), summary (one-line pointer), off")
	f.StringVar(&autopilotOliumProvider, "provider", "", oliumProviderFlagUsage)
	f.StringVar(&autopilotOliumModel, "model", "", "Olium model id override (falls back to agent.olium.model)")
	f.StringVar(&autopilotSystemPrompt, "system-prompt", "", "Replace the built-in autopilot system prompt with this value (full replace; browser section is not auto-appended)")
	f.StringVar(&autopilotSystemPromptFile, "system-prompt-file", "", "Path to a file whose contents replace the built-in autopilot system prompt (takes precedence over --system-prompt)")
	f.StringVar(&autopilotOliumOAuthCred, "oauth-cred", "", "Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS)")
	f.StringVar(&autopilotOliumOAuthToken, "oauth-token", "", "Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	f.StringVar(&autopilotOliumLLMAPIKey, "llm-api-key", "", "Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var)")
	f.StringVar(&autopilotSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --source)")
	f.StringVar(&autopilotPrompt, "prompt", "", "Free-text task guidance for the agent (same as the positional [prompt]; use --plan-file for a whole plan with seed HTTP requests)")
	f.StringSliceVar(&autopilotSkills, "skill", nil, "Force-load these skills by name, bypassing the pre-flight selection (repeatable or comma-separated)")
	f.StringSliceVar(&autopilotSkillTags, "skill-tag", nil, "Force-load every skill carrying one of these tags (e.g. xss,idor)")
	f.BoolVar(&autopilotNoSkillFilter, "no-skill-filter", false, "Load the full skill set; skip the pre-flight skill selection")
	f.DurationVar(&autopilotMaxDuration, "max-duration", 6*time.Hour, "Maximum wall-clock duration for the autopilot session (e.g. 1h, 6h)")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.BoolVar(&autopilotShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.StringVar(&autopilotPlanFile, "plan-file", "", "Path to a plan file mixing free-text guidance and raw HTTP request(s). Owns the instruction + seed input; cannot be combined with --input or a prompt (--prompt / positional)")
	// The browser is always available for autopilot (agent.browser.enable defaults
	// to true), so there is no --browser flag. Credentials and the auth-preflight
	// signals (auth-required, browser-start-url, focus routes) are taken from the
	// prompt — e.g. `autopilot "log in as admin/admin123, focus on /admin"`.
	f.BoolVar(&autopilotHeaded, "headed", false, "Show the browser window during the run (native pre-scan spidering, in-process probes, and agent-browser subprocesses); sets VIGOLIUM_BROWSER_HEADED=1 for the run. Debugging aid.")
	_ = f.MarkHidden("headed")
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
	f.StringVar(&autopilotResume, "resume", "", "Resume a previous durable-autopilot run by its agentic-scan UUID: reuses its session dir, project, target, and durable scratchpad/candidates; skips pre-scan and audit re-prep (requires agent.olium.autopilot_mode != legacy)")
	f.StringVar(&autopilotSessionDir, "session-dir", "", "Explicit session directory for this run's debug artifacts (transcript.jsonl, runtime.log, scratchpad, tool-results). Default: <agent.sessions_dir>/<run-uuid>. Pin it to know exactly where to look when debugging (e.g. alongside -S/--stateless scans).")
	f.StringVar(&autopilotTranscript, "transcript", "", "After the run, also copy the session's transcript.jsonl to this path. The in-session copy is always kept; this is a convenience for debugging (e.g. keep the transcript when the DB is throwaway).")
	f.StringVar(&autopilotKnowledgeBase, "knowledge-base", "", "Path to a file or directory describing the app. Prose docs (markdown/txt/rst/…) are LLM-distilled into a compact brief + document index front-loaded into the operator (full docs stay on disk, read on demand). HTTP-traffic exports in the same path (HAR, Burp XML, curl, OpenAPI/Swagger, Postman, URL lists, raw HTTP) are auto-detected, parsed, and ingested into the project DB as normal traffic (source=knowledge-base) with a sample folded into the brief — disable with --knowledge-base-no-traffic. Works blackbox and whitebox.")
	f.BoolVar(&autopilotKnowledgeBaseRaw, "knowledge-base-raw", false, "Skip the LLM distillation of --knowledge-base: front-load a deterministic document index only (offline / reproducible). No-op without --knowledge-base.")
	f.BoolVar(&autopilotKnowledgeBaseNoTraffic, "knowledge-base-no-traffic", false, "Do not parse HTTP-traffic-format files (HAR, Burp XML, curl, OpenAPI/Swagger, Postman, URL lists, raw HTTP) found in --knowledge-base into normal traffic; treat every file as prose docs instead. By default such files are parsed and ingested into the project DB (source=knowledge-base). No-op without --knowledge-base.")
}

func runAgentAutopilot(cmd *cobra.Command, args []string) (err error) {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Natural-language prompt handling. The task guidance comes from either the
	// positional [prompt] or --prompt (same slot). With no explicit structured
	// flags, it drives the run through the LLM intent parser (extracts
	// target/source/focus). With structured flags present, the prompt is NOT
	// discarded — it is preserved verbatim as instruction context (scope rules,
	// exploitation hints), while explicit flags still win for structured fields.
	rawPrompt, err := resolveRawPrompt(args, autopilotPrompt, autopilotPlanFile)
	if err != nil {
		return err
	}
	// --resume counts as explicit input: the run's target/source is restored from
	// the stored AgenticScan later, so a bare guidance prompt (`--resume <uuid>
	// --prompt "focus on the remaining IDOR"`) must not be routed through target
	// extraction — it carries no target and would either abort or overwrite the
	// resumed one. It is preserved verbatim as instruction context instead.
	hasExplicitFlags := autopilotTarget != "" || autopilotInput != "" || autopilotRecordUUID != "" || autopilotSource != "" || autopilotPlanFile != "" || autopilotResume != ""
	if rawPrompt != "" && !hasExplicitFlags {
		return runAutopilotFromPrompt(rawPrompt)
	}
	if rawPrompt != "" {
		autopilotInstructionPrefix = rawPrompt
	}

	intensity, err := agent.ValidateIntensity(autopilotIntensity)
	if err != nil {
		return err
	}

	autopilotPriorContext, err = validatePriorContextMode(autopilotPriorContext)
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
			"no-prescan": cmd.Flags().Changed("no-prescan"),
		}
		// Browser is not overridable from the CLI (always on), so it is omitted
		// here — the preset's Browser:true wins and the result's Browser is unused.
		intensityResult := agent.ResolveAutopilotIntensity(intensity, agent.AutopilotIntensityPreset{
			MaxCommands:     autopilotMaxCommands,
			Timeout:         autopilotMaxDuration,
			AuditDriverMode: auditModeLocal,
			NoPrescan:       autopilotNoPrescan,
		}, changed)
		autopilotMaxCommands = intensityResult.MaxCommands
		autopilotMaxDuration = intensityResult.Timeout
		if !noAudit {
			autopilotAudit = intensityResult.AuditDriverMode
		}
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

	// --resume: continue an existing durable-autopilot run. Rewires target /
	// source / project / session identity from the stored AgenticScan so the
	// operator re-enters seeded from the durable scratchpad + candidate ledger.
	// Mutually exclusive with the seed-input flags (resume reuses the original
	// target, not a fresh seed). Runs before the Burp import so the resumed
	// project is settled first; prepareAutopilotResume pins it authoritatively
	// (clicommon.PinProjectUUID), so scoping no longer depends on this ordering.
	if autopilotResume != "" {
		if autopilotInput != "" || autopilotRecordUUID != "" || autopilotPlanFile != "" {
			return fmt.Errorf("--resume cannot be combined with --input/--record-uuid/--plan-file")
		}
		if err := prepareAutopilotResume(context.Background(), repo, autopilotResume, settings.Agent.EffectiveSessionsDir()); err != nil {
			return err
		}
	}

	// --burp-bridge-url: pull live Burp Proxy history into the project DB before
	// the pre-scan and operator start, so the agent mines that traffic (and any
	// prior findings) instead of only what a fresh scan produces. Idempotent
	// (insert new, refresh changed, skip unchanged). Non-fatal on failure. Kept
	// after the resume block so it imports into the resumed project (which resume
	// has already pinned via clicommon.PinProjectUUID).
	if bridge := strings.TrimSpace(autopilotBurpBridgeURL); bridge != "" && repo != nil {
		validated, verr := burpbridge.ValidateURL(bridge)
		if verr != nil {
			return fmt.Errorf("--burp-bridge-url: %w", verr)
		}
		projectUUID, _ := resolveProjectUUID()
		fmt.Fprintf(os.Stderr, "%s Importing live Burp traffic from %s ...\n",
			terminal.InfoSymbol(), terminal.Cyan(validated))
		res, ierr := importBurpTrafficToDB(context.Background(), repo, validated,
			burpbridge.Query{Location: "proxy_history"}, projectUUID)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "%s Burp bridge import failed: %v — continuing without it\n",
				terminal.WarningSymbol(), ierr)
		} else {
			fmt.Fprintf(os.Stderr, "%s Imported Burp traffic: %d stored (%d new, %d updated, %d unchanged)\n",
				terminal.SuccessSymbol(), res.Stored(), res.Inserted, res.Updated, res.Unchanged)
		}
	}

	// Resolve --plan-file into an instruction + --input before the generic
	// resolvers run. Autopilot is single-seed: the first request block is the
	// live seed, the rest become labelled context in the instruction.
	if autopilotPlanFile != "" {
		// resolvePlanFile owns the --input conflict (the prompt conflict is
		// caught earlier in resolveRawPrompt); --record-uuid is checked here
		// because it's autopilot-only (it resolves to a single seed, which the
		// plan file already supplies). Swarm has no equivalent: its --record-uuid
		// is multi-valued and just adds more seeds alongside the plan's, so
		// combining is allowed there.
		if autopilotRecordUUID != "" {
			return fmt.Errorf("--plan-file cannot be combined with --record-uuid")
		}
		planInstruction, planRequests, perr := resolvePlanFile(autopilotPlanFile, autopilotInput)
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

	// autopilotInstruction is populated only by --plan-file (above); the raw
	// prompt (--prompt / positional) is layered in front as the verbatim prefix.
	instruction := prependVerbatimPrompt(autopilotInstruction, autopilotInstructionPrefix)

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

	// --knowledge-base: validate the path up front so a typo fails fast rather
	// than surfacing deep in the run. Expanded to an absolute path here; the
	// docs are gathered + distilled later in runAutopilotOlium (which has the
	// resolved provider + session dir) and folded into the operator's brief.
	if autopilotKnowledgeBase != "" {
		expanded := config.ExpandPath(autopilotKnowledgeBase)
		if _, statErr := os.Stat(expanded); statErr != nil {
			return fmt.Errorf("--knowledge-base %q: %w", autopilotKnowledgeBase, statErr)
		}
		autopilotKnowledgeBase = expanded
	}

	// Explicit-flag path: the prompt was passed verbatim (never parsed), so pull
	// any credentials / auth intent out of it here. cmd != nil distinguishes this
	// from the NL re-entry (runAutopilotFromPrompt → runAgentAutopilot(nil, nil)),
	// which already populated the auth vars via applyIntentToAutopilotFlags.
	// Skipped under --dry-run so a preview never makes a live LLM call.
	if cmd != nil && !autopilotDryRun {
		extractPromptAuthIntent(settings, repo, autopilotInstructionPrefix)
	}

	// Descend from the command's context (Cobra wires signal cancellation into
	// it) so Ctrl-C / deadline propagates into the run.
	ctx := context.Background()
	if cmd != nil {
		ctx = cmd.Context()
	}
	return runAutopilotOlium(ctx, settings, repo, instruction)
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

	// Multi-app: run each app one at a time (autopilot overrides shared flags
	// per app, so runs must be serialized — see runMultiAppAutopilot).
	fmt.Fprintf(os.Stderr, "%s Parsed %d apps from prompt, running sequentially\n",
		terminal.InfoSymbol(), len(intent.Apps))
	return runMultiAppAutopilot(context.Background(), engine, settings, repo, intent)
}

// applyAuthIntentToAutopilot copies auth/browser signals extracted by the LLM
// intent parser into the autopilot vars, without overwriting values already set.
// Shared by the NL-prompt path (applyIntentToAutopilotFlags) and the explicit-
// flag path (extractPromptAuthIntent). It is the sole way these vars get
// populated now that --credentials / --auth-required / --requires-browser /
// --browser-start-url / --focus-routes no longer exist as flags.
func applyAuthIntentToAutopilot(app agent.AppIntent) {
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
}

// extractPromptAuthIntent runs the LLM intent parser on the prompt purely to
// pull auth/browser signals into the autopilot vars on the explicit-flag path,
// where the prompt is otherwise passed verbatim and never parsed — so
// `autopilot -t <url> "log in as admin/admin123, focus on /admin"` still
// pre-authenticates. Target/source are owned by the explicit flags and left
// untouched (ParseScanIntent does no target resolution). Best-effort: a parse
// failure is logged and the run continues unauthenticated, as before.
func extractPromptAuthIntent(settings *config.Settings, repo *database.Repository, prompt string) {
	if app, ok := parsePromptFirstApp(settings, repo, prompt, "autopilot", autopilotTarget, autopilotSource); ok {
		applyAuthIntentToAutopilot(app)
	}
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
	// Browser is always on for autopilot, so app.Browser is a no-op here.
	applyAuthIntentToAutopilot(app)
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

// runMultiAppAutopilot runs autopilot for multiple apps one at a time. Each app
// temporarily overrides the package-level flags and re-enters runAutopilotOlium,
// so every app gets the same olium-backed treatment as a single-app invocation.
// Runs are strictly SEQUENTIAL (not the parallel fan-out swarm uses): the
// per-app flag override/restore mutates shared package globals, so concurrent
// runs would race and cross-contaminate targets/sources.
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

	return runMultiAppSequential(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		fmt.Fprintf(os.Stderr, "%s [%d/%d] Starting autopilot: target=%s source=%s\n",
			terminal.InfoSymbol(), idx+1, len(intent.Apps),
			clicommon.ValueOrNone(app.Target),
			clicommon.ValueOrNone(terminal.ShortenHome(app.SourcePath)))

		instruction := mergeIntentInstruction(autopilotInstruction, app)
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

		return runAutopilotOlium(ctx, settings, repo, instruction)
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
