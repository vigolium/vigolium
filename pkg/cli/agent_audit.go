package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	auditDriver        string
	auditIntensity     string
	auditMode          string
	auditModes         string
	auditListModes     bool
	auditSource        string
	auditNoStream      bool
	auditShowThinking  bool
	auditUploadResults bool
	auditInteractive   bool

	// Resolved mode chain (intensity- or --modes-derived) and the
	// per-driver filtered chains, populated by runAgentAudit and consumed
	// by runAuditDriver. audit gets the modes it understands; piolium
	// gets the modes it understands. For driver=auto/both these may
	// differ (per-driver skip-unsupported).
	auditModeChain    []string
	auditDriverModes  []string
	auditPioliumModes []string
	auditCommitDepth  int
	auditNoDedup      bool
	auditKeepRaw      bool
	auditCleanRaw     bool
	auditProvider     string
	auditAgent        string

	// auditStateless (-S) runs the audit into a throwaway temp DB (the main
	// DB is left untouched) and auto-emits a self-contained HTML report,
	// mirroring `vigolium scan -S`. auditReportOutput (-o) overrides the
	// report destination.
	auditStateless    bool
	auditReportOutput string

	// auditOutputDir (--output-dir) bundles a --stateless run's HTML report
	// and a copy of the raw vigolium-results/ tree(s) into one directory. A
	// relative -o is nested under it; the source-tree copy is left in place
	// (per --keep-raw). Only applies with -S/--stateless.
	auditOutputDir string

	auditPiProvider string
	auditPiModel    string

	auditNoPreflight      bool
	auditPreflightTimeout time.Duration

	auditPlmScanLimit       int
	auditPlmScanSince       string
	auditPlmPhaseRetries    int
	auditPlmCommandRetries  int
	auditPlmLongshotLimit   int
	auditPlmLongshotTimeout int
	auditPlmLongshotLangs   string

	// BYOK auth override flags. Apply to whichever driver(s) actually
	// run — audit receives them as --api-key/--oauth-token/--oauth-cred-file
	// flags; piolium receives them as env vars on the pi subprocess
	// (and, for codex cred files, a staged <pi-agent-dir>/auth.json).
	// Each accepts literal, $ENV_NAME, or @path indirection (CLI only —
	// REST treats values as literal). At most one may be set.
	auditAPIKey        string
	auditOAuthToken    string
	auditOAuthCredFile string
)

var agentAuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run audit and/or piolium back-to-back as a unified security audit",
	Long: `Run a unified security audit that drives audit and/or piolium against
the same source tree under a single AgenticScan, with post-pass findings
deduplication.

Driver selection (--driver):
  auto       preflight the resolved coding-agent CLI (claude or codex) on
             PATH; if present run audit, else fall back to piolium without
             ever launching the embedded binary (default). Mid-run audit
             failures surface — piolium is not silently retried.
  both       run audit then piolium unconditionally (sequential)
  audit      run only audit
  piolium    run only piolium (no audit, no fallback)

When --driver=auto or --driver=both, --mode is restricted to modes both
drivers understand:
lite, balanced, deep, revisit, confirm, merge. To use a driver-specific
mode (piolium's longshot/smoke or audit's reinvest/mock), pass
--driver=piolium or --driver=audit explicitly.

Each driver runs in its own session subdirectory ({session}/vigolium-results/ and
{session}/piolium/) under one parent AgenticScan UUID. Per-driver runtime
logs, audit-state.json, and findings stay separated on disk and in the DB
(child AgenticScan rows), but are scored as one logical audit. After both
drivers complete, a project-wide findings dedup collapses (module_id,
severity, url) duplicates that escaped INSERT-time hash dedup.

Under --driver=both, if one driver fails the other still runs and the
parent run reports per-driver status. Under --driver=auto, piolium runs
only when the audit driver's claude/codex CLI is missing from PATH; a
mid-run audit failure surfaces directly without silently switching.
Use --driver=piolium or --driver=audit when you only want one harness's
perspective.

--interactive (-i) drops you into the coding agent with the audit
harness installed and lets you drive the audit yourself (audit-only).
It skips NDJSON streaming, the AgenticScan row, and findings
auto-import: audit writes results to <source>/vigolium-results/, which you then
load and turn into a report in one command with
'vigolium import <source>/vigolium-results --format html -o audit-report.html'.`,
	RunE: runAgentAudit,
}

// auditCmd mirrors agentAuditCmd at the top level so users can invoke a
// unified audit with `vigolium audit` without typing the `agent` parent,
// matching the `vigolium olium` alias. Both share the package-level flag
// state via registerAuditFlags, so either entry point behaves identically.
// Long/Example are wired from agentAuditCmd / usage.go so they stay in sync.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a unified security audit (alias for `vigolium agent audit`)",
	Long:  agentAuditCmd.Long,
	RunE:  runAgentAudit,
}

func init() {
	agentCmd.AddCommand(agentAuditCmd)
	rootCmd.AddCommand(auditCmd)

	registerAuditFlags(agentAuditCmd)
	registerAuditFlags(auditCmd)
}

// registerAuditFlags wires the shared audit flag set onto a cobra command.
// The backing variables are package-level, so agentAuditCmd and auditCmd
// read from the same state regardless of which entry point is invoked.
func registerAuditFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&auditDriver, "driver", agent.AuditDriverAuto, "Audit driver: auto (audit; fall back to piolium when claude/codex CLI missing), both (audit then piolium), audit, or piolium (default auto)")
	f.StringVar(&auditIntensity, "intensity", "balanced", "Audit intensity preset: quick, balanced, or deep")
	f.StringVar(&auditMode, "mode", "", "Audit mode override (overrides --intensity). Shared modes: lite, balanced, deep, revisit, confirm, merge. Driver-specific: piolium=longshot/smoke/diff/status, audit=reinvest/refresh/mock/diff/status")
	f.StringVar(&auditModes, "modes", "", "Run a chain of modes back-to-back (comma-separated, e.g. deep,refresh,confirm). Overrides --mode/--intensity. Stops on the first non-complete mode. audit runs the chain natively (--modes); piolium chains via sequential runs collapsed into one row; with driver=auto/both, modes a driver can't run are skipped on that driver's leg.")
	f.BoolVar(&auditListModes, "list-modes", false, "List the available audit modes (audit's mode graph: phases, time estimate, descriptions) and exit")
	f.StringVar(&auditSource, "source", ".", "Source: local directory, git URL, gs://<project>/<key> archive, or local .zip/.tar.gz")
	f.BoolVarP(&auditInteractive, "interactive", "i", false, "Drop into the coding agent with the audit harness installed and drive the audit yourself (audit-only; the embedded vigolium-audit binary's -i). Skips NDJSON streaming, the AgenticScan row, and findings auto-import — results land in <source>/vigolium-results/; import them afterward with 'vigolium import'. Not valid with --driver=piolium.")
	f.BoolVar(&auditNoStream, "no-stream", false, "Don't echo agent output to the console (still written to {session}/<driver>/runtime.log)")
	f.BoolVar(&auditShowThinking, "show-thinking", false, "Render the agent's internal thinking blocks (audit NDJSON 'thinking' events) in the live stream. Off by default — thinking is verbose and produces many lines per phase.")
	f.BoolVar(&auditUploadResults, "upload-results", false, "Upload session bundle to cloud storage after completion (requires storage config)")
	f.IntVar(&auditCommitDepth, "commit-depth", 1, "git clone --depth value when --source is a git URL (default 1; use 0 for full history; overrides --intensity)")
	f.BoolVar(&auditNoDedup, "no-dedup", false, "Skip the post-pass project-wide findings dedup that runs after the audit completes")
	f.BoolVar(&auditKeepRaw, "keep-raw", true, "[audit] Keep raw scanner output, draft findings, and intermediate workspaces under <source>/vigolium-results/ for manual review (overrides audit's deep/confirm auto-prune). On by default; the source-folder copy is also retained. Pass --clean-raw to remove it from the source tree. No effect on the piolium leg.")
	f.BoolVar(&auditCleanRaw, "clean-raw", false, "[audit] Remove <source>/vigolium-results/ from the source tree after the run (the session copy is always kept). Inverts the default --keep-raw retention of the source-folder copy. No effect on the piolium leg.")
	f.BoolVarP(&auditStateless, "stateless", "S", false, "Run the audit into a throwaway temporary database (the main DB is left untouched) and auto-write a self-contained HTML report. Mirrors 'vigolium scan -S'. Not valid with --interactive.")
	f.StringVarP(&auditReportOutput, "output", "o", "", "HTML report path for --stateless runs (default vigolium-result/vigolium-audit-report.html; supports gs://<project>/<key> and {ts}). Only applies with -S/--stateless.")
	f.StringVar(&auditOutputDir, "output-dir", "", "Bundle directory for --stateless runs: collects the HTML report (as vigolium-audit-report.html) AND a copy of the raw vigolium-results/ output into one folder. A relative -o/--output is nested under it; an absolute path or gs:// URL wins. The source-tree copy is left in place. Supports {ts}/{project-uuid}. Only applies with -S/--stateless.")

	// Audit-only. audit now drives both Claude Code and Codex
	// internally, so anthropic-* and openai-* providers are both
	// accepted; ResolveAuditDriverInvocation maps the prefix to the right
	// `--agent` value.
	f.StringVar(&auditProvider, "provider", "", "[audit] Olium provider hint to drive audit's --agent: anthropic-* → claude, openai-* → codex (also forwards that provider's BYOK auth). Empty inherits agent.olium.provider. For a pure agent switch without changing auth, prefer --agent.")
	f.StringVar(&auditAgent, "agent", "", "[audit] Coding agent for the audit leg: claude or codex. Overrides the agent implied by --provider while keeping its resolved auth. No effect on the piolium leg.")

	// Piolium-only.
	f.StringVar(&auditPiProvider, "pi-provider", "", "[piolium] Override pi's defaultProvider (e.g. vertex-anthropic, google-vertex)")
	f.StringVar(&auditPiModel, "pi-model", "", "[piolium] Override pi's defaultModel (e.g. claude-opus-4-6, gemini-3.1-pro)")
	f.BoolVar(&auditNoPreflight, "no-preflight", false, "Skip the pre-audit roundtrip checks for both drivers (pi+claude auth/model availability)")
	f.DurationVar(&auditPreflightTimeout, "preflight-timeout", piolium.DefaultPreflightTimeout, "Per-driver preflight timeout (e.g. 30s, 1m); applies to both pi and claude")
	f.IntVar(&auditPlmScanLimit, "plm-scan-limit", 0, "[piolium] Cap commit-history scan to N commits (0=piolium default)")
	f.StringVar(&auditPlmScanSince, "plm-scan-since", "", `[piolium] Cap commit-history scan to a git --since window (e.g. "60 days ago")`)
	f.IntVar(&auditPlmPhaseRetries, "plm-phase-retries", 0, "[piolium] Per-phase retry count (0=piolium default)")
	f.IntVar(&auditPlmCommandRetries, "plm-command-retries", 0, "[piolium] Per-command retry count (0=piolium default)")
	f.IntVar(&auditPlmLongshotLimit, "plm-longshot-limit", 0, "[piolium] Max files hunted in longshot mode (0=piolium default)")
	f.IntVar(&auditPlmLongshotTimeout, "plm-longshot-timeout", 0, "[piolium] Per-file kill timer in longshot mode in ms (0=piolium default)")
	f.StringVar(&auditPlmLongshotLangs, "plm-longshot-langs", "", "[piolium] Longshot language allowlist (comma-separated, e.g. python,go)")

	// BYOK overrides. Each accepts literal, $ENV_NAME, or @path. Mutually
	// exclusive — at most one wins. Apply to whichever driver(s) actually
	// run on this invocation; the underlying mapping is described in
	// pkg/agent/auth_override.go.
	f.StringVar(&auditAPIKey, "api-key", "", "BYOK API key for the run (literal, $ENV_NAME, or @path). claude→ANTHROPIC_API_KEY, codex→OPENAI_API_KEY. Empty inherits agent.olium.* config. Mutually exclusive with --oauth-token / --oauth-cred-file.")
	f.StringVar(&auditOAuthToken, "oauth-token", "", "BYOK Anthropic OAuth bearer token (literal, $ENV_NAME, or @path). Claude only — produced by 'claude setup-token'. Mutually exclusive with --api-key / --oauth-cred-file.")
	f.StringVar(&auditOAuthCredFile, "oauth-cred-file", "", "BYOK OAuth credential file path (literal or $ENV_NAME). Codex ('~/.codex/auth.json' shape). Staged under <pi-agent-dir>/auth.json with backup-and-restore for piolium runs. Mutually exclusive with --api-key / --oauth-token.")
}

// driverPlan tags one driver's invocation: the harness identity, where its
// session subdir lives, and (after Run) the captured outcome that feeds
// the combined banner.
type driverPlan struct {
	name       string // "audit" or "piolium"
	sessionDir string

	// Set after the driver runs. AuditRunner so a multi-mode piolium
	// chain (*agent.PioliumChainScanner) is a drop-in for a single
	// *agent.AuditAgenticScanner.
	runner agent.AuditRunner
	runErr error
}

func runAgentAudit(cmd *cobra.Command, args []string) error {
	// --list-modes is an early-return info flag: print audit's mode
	// graph and exit before requiring --source / settings / a DB.
	if auditListModes {
		return runListModes(false)
	}

	// --stateless (-S): run the whole audit against a throwaway temp DB so
	// the main DB is untouched, then auto-emit a self-contained HTML report
	// (mirrors `vigolium scan -S`). Repoint globalDB at the scratch before
	// the first getDB() so every DB access in this run opens it. The
	// temp-file removal defer is registered here — before defer
	// closeDatabaseOnExit() — so LIFO ordering removes the file only after
	// the DB connection is closed.
	if auditStateless {
		if auditInteractive {
			return fmt.Errorf("--stateless/-S cannot be combined with --interactive (interactive bypasses the database and report import)")
		}
		tmpFile, tmpErr := os.CreateTemp("", "vigolium-audit-stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("create temporary database: %w", tmpErr)
		}
		statelessDBPath := tmpFile.Name()
		_ = tmpFile.Close()
		defer func() {
			_ = os.Remove(statelessDBPath)
			_ = os.Remove(statelessDBPath + "-wal")
			_ = os.Remove(statelessDBPath + "-shm")
		}()
		globalDB = statelessDBPath
	}

	defer syncLogger()
	defer closeDatabaseOnExit()

	if !agent.IsValidAuditDriver(auditDriver) {
		return fmt.Errorf("invalid --driver %q (must be: auto, both, audit, or piolium)", auditDriver)
	}

	// --agent is a pure agent selector for the audit leg. Reject bad
	// values up front rather than silently falling back to the
	// provider-derived agent. It has no piolium equivalent, so warn
	// (don't error) when it can't take effect on a piolium-only run.
	auditAgent = strings.TrimSpace(auditAgent)
	if auditAgent != "" {
		if !agent.IsValidAuditDriverAgent(auditAgent) {
			return fmt.Errorf("invalid --agent %q (must be: claude or codex)", auditAgent)
		}
		if auditDriver == agent.AuditDriverPiolium {
			fmt.Fprintf(os.Stderr, "%s --agent is audit-only and has no effect with --driver=piolium\n",
				terminal.WarningSymbol())
		}
	}

	// --interactive hands the terminal to the user inside the coding
	// agent (audit's -i). piolium has no equivalent, so combining it
	// with --driver=piolium is contradictory; auto/both/audit all run
	// the audit leg interactively (the piolium leg is dropped).
	if auditInteractive && auditDriver == agent.AuditDriverPiolium {
		return fmt.Errorf("--interactive is audit-only and cannot be combined with --driver=piolium (omit --driver or use --driver=audit)")
	}

	// --keep-raw / --clean-raw are audit-only. keep-raw is on by default, so
	// only flag the conflict when the operator explicitly set both, and only
	// warn about the piolium no-op when they explicitly opted into keep-raw
	// (otherwise the default-on flag would warn on every --driver=piolium run).
	keepRawSet := cmd != nil && cmd.Flags().Changed("keep-raw")
	if auditCleanRaw && keepRawSet && auditKeepRaw {
		return fmt.Errorf("--keep-raw and --clean-raw are mutually exclusive (omit --keep-raw, which is on by default, to clean the source folder)")
	}
	if auditDriver == agent.AuditDriverPiolium {
		if keepRawSet && auditKeepRaw {
			fmt.Fprintf(os.Stderr, "%s --keep-raw is audit-only and has no effect with --driver=piolium\n",
				terminal.WarningSymbol())
		}
		if auditCleanRaw {
			fmt.Fprintf(os.Stderr, "%s --clean-raw is audit-only and has no effect with --driver=piolium\n",
				terminal.WarningSymbol())
		}
	}

	// -o/--output and --output-dir only shape the --stateless report/bundle;
	// warn (don't error) when either is set without -S so the run still proceeds.
	warnIgnoredWithoutStateless := func(flag, val string) {
		if strings.TrimSpace(val) != "" && !auditStateless {
			fmt.Fprintf(os.Stderr, "%s %s only applies with --stateless/-S; ignoring\n",
				terminal.WarningSymbol(), flag)
		}
	}
	warnIgnoredWithoutStateless("-o/--output", auditReportOutput)
	warnIgnoredWithoutStateless("--output-dir", auditOutputDir)

	// -S without --output-dir: the report is still written, but the raw
	// vigolium-results/ tree is only left under <source>/ and the session dir.
	// Nudge the operator toward bundling the report + raw results into one
	// folder. (auditStateless implies !auditInteractive — rejected above.)
	if auditStateless && strings.TrimSpace(auditOutputDir) == "" {
		fmt.Fprintf(os.Stderr, "%s --stateless without --output-dir: raw scanner output stays under <source>/vigolium-results/; pass --output-dir <dir> to bundle the report and raw results together\n",
			terminal.WarningSymbol())
	}

	intensity, err := agent.ValidateIntensity(auditIntensity)
	if err != nil {
		return err
	}
	explicitModes := agent.ParseModesCSV(auditModes)
	if cmd != nil {
		changed := map[string]bool{
			"modes":        len(explicitModes) > 0,
			"mode":         cmd.Flags().Changed("mode"),
			"commit-depth": cmd.Flags().Changed("commit-depth"),
		}
		preset := agent.ResolveAuditDriverIntensity(intensity, agent.AuditDriverIntensityPreset{
			Mode:        auditMode,
			Modes:       explicitModes,
			CommitDepth: auditCommitDepth,
		}, changed)
		auditMode = preset.Mode
		auditModeChain = preset.Modes
		auditCommitDepth = preset.CommitDepth
	} else {
		auditModeChain = []string{auditMode}
	}

	auditChain, pioliumModes, err := agent.ValidateAuditDriverModes(
		auditDriver, auditModeChain, piolium.IsValidMode, agent.IsValidAuditDriverMode)
	if err != nil {
		return err
	}
	auditDriverModes = auditChain
	auditPioliumModes = pioliumModes
	if auditSource == "" {
		return fmt.Errorf("--source is required (local path or git URL)")
	}

	// Interactive mode always drives audit, so the embedded binary must
	// be present and the resolved chain must contain at least one mode
	// audit understands. Fail before the git clone.
	if auditInteractive {
		if !bin.Available() {
			return fmt.Errorf("--interactive requires the embedded vigolium-audit binary — run `make build-audit` and rebuild vigolium")
		}
		if len(auditDriverModes) == 0 {
			return fmt.Errorf("--interactive runs the audit leg, but mode chain %q contains no audit-supported modes", agent.JoinModes(auditModeChain))
		}
	}
	// --provider is now permissive — anthropic-* + openai-* both
	// resolve via ResolveAuditDriverInvocation. Empty inherits olium config.

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// agent.audit.default_agent is a persistent pure agent selector for the
	// audit leg; reject a bad value up front rather than silently ignoring it
	// (ForceAuditDriverAgent treats anything other than claude/codex as a
	// no-op, which would mask the typo).
	if da := strings.TrimSpace(settings.Agent.Audit.DefaultAgent); da != "" && !agent.IsValidAuditDriverAgent(strings.ToLower(da)) {
		return fmt.Errorf("invalid agent.audit.default_agent %q (must be: claude or codex)", da)
	}

	// BYOK auth override resolution. Indirection ($ENV / @path) is CLI-only
	// — the REST endpoint treats values as literals to avoid letting a
	// network-supplied string probe the server's process env. The resolved
	// override carries the agent (claude/codex) it applies to so both
	// drivers see the same answer.
	authOverride, err := resolveAuditAuthOverride(auditAPIKey, auditOAuthToken, auditOAuthCredFile, auditProvider, settings.Agent.Olium.Provider)
	if err != nil {
		return err
	}

	// When the audit leg participates, validate that the agent it will
	// actually run (after --agent / --provider / agent.audit.default_agent
	// precedence) can use the resolved auth. A pure agent selector keeps the
	// provider/BYOK auth, so e.g. default_agent=codex + a claude OAuth token
	// is a mismatch — surface it now instead of as a cryptic subprocess exit.
	// The piolium leg is unaffected (its agent is pi's, not --agent's).
	if agent.DriverIncludesAudit(auditDriver) {
		inv := resolveAuditDriverInvocation(settings.Agent.Olium, settings.Agent.Audit.DefaultAgent, authOverride)
		if err := agent.ValidateAuditDriverInvocation(inv); err != nil {
			return fmt.Errorf("audit agent/auth mismatch: %w", err)
		}
	}

	// Fail fast (before the git clone) only when the requested driver
	// cannot possibly run. This probe is silent: the per-driver
	// availability warnings — in particular the "piolium runtime
	// unavailable; skipping piolium" message — are deferred to the
	// orchestration step so they only surface when piolium is actually
	// chosen or about to run, not on every audit invocation.
	if err := ensureAuditDriversFeasible(auditDriver); err != nil {
		return err
	}

	parentUUID := pinnedOrNewUUID(globalScanUUID)
	parentSessionDir, err := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), parentUUID)
	if err != nil {
		return fmt.Errorf("create parent session dir: %w", err)
	}

	projectUUID, _ := resolveProjectUUID()

	// One source resolve, two drivers — avoids cloning the same git URL twice.
	resolveSource := auditSource
	if storage.IsGCSURI(resolveSource) {
		fmt.Fprintf(os.Stderr, "%s Downloading %s\n", terminal.InfoSymbol(), terminal.Cyan(resolveSource))
		extractedPath, cleanup, gcsErr := storage.ResolveGCSSource(&settings.Storage, resolveSource, projectUUID)
		if gcsErr != nil {
			return fmt.Errorf("resolve gs:// source: %w", gcsErr)
		}
		defer cleanup()
		resolveSource = extractedPath
	}
	absTarget, _, _, err := agent.ResolveSourceAndDiff(
		resolveSource, "", 0, nil, parentSessionDir,
		agent.WithCloneDepth(auditCommitDepth),
	)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	if absTarget == "" {
		return fmt.Errorf("source path could not be resolved: %s", auditSource)
	}

	// Interactive: hand the terminal to the user inside the coding agent
	// with audit's harness installed. This bypasses the headless
	// orchestrator entirely — no AgenticScan rows, no NDJSON decode, no
	// findings auto-import. audit writes to <source>/vigolium-results/; the
	// operator imports + exports afterward (hint printed below).
	if auditInteractive {
		invocation := resolveAuditDriverInvocation(settings.Agent.Olium, settings.Agent.Audit.DefaultAgent, authOverride)
		cfg := agent.BuildAuditDriverCfg(agent.AuditDriverCfgInput{
			Mode:                  agent.FirstMode(auditDriverModes),
			Modes:                 auditDriverModes,
			SourcePath:            absTarget,
			SessionDir:            parentSessionDir,
			ProjectUUID:           projectUUID,
			ScanUUID:              globalScanUUID,
			ParentAgenticScanUUID: parentUUID,
			Invocation:            invocation,
			Stream:                false,
			KeepRaw:               auditKeepRaw,
			KeepSourceOutputDir:   keepSourceResults(),
			AuthOverride:          authOverride,
		})

		fmt.Fprintf(os.Stderr, "%s %s\n",
			terminal.Green(terminal.SymbolStart),
			terminal.BoldHiBlue("Interactive Audit (audit)"))
		fmt.Fprintf(os.Stderr, "  %s Mode: %s | Agent: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(agent.JoinModes(auditDriverModes)),
			terminal.HiTeal(string(invocation.Agent)))
		fmt.Fprintf(os.Stderr, "  %s Source: %s\n",
			terminal.Purple(terminal.SymbolTarget),
			terminal.HiTeal(terminal.ShortenHome(absTarget)))
		fmt.Fprintf(os.Stderr, "  %s %s\n\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("handing the terminal to the coding agent — drive the audit yourself"))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		runErr := agent.RunAuditDriverInteractive(ctx, cfg)

		auditDirLocal := filepath.Join(absTarget, "audit")
		fmt.Fprintln(os.Stderr)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "%s interactive audit session exited with error: %v\n",
				terminal.WarningSymbol(), runErr)
		} else {
			fmt.Fprintf(os.Stderr, "%s interactive audit session ended\n", terminal.SuccessSymbol())
		}
		fmt.Fprintf(os.Stderr, "%s Next step — import the on-disk results and write a report in one command:\n",
			terminal.Purple(terminal.SymbolInfo))
		fmt.Fprintf(os.Stderr, "  %s %s\n",
			terminal.Gray(terminal.SymbolDot),
			terminal.HiCyan(fmt.Sprintf("vigolium import %s --format html -o audit-report.html", terminal.ShortenHome(auditDirLocal))))
		return runErr
	}

	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	startedAt := time.Now()
	if repo != nil {
		parentRow := &database.AgenticScan{
			UUID:        parentUUID,
			ProjectUUID: projectUUID,
			ScanUUID:    globalScanUUID,
			Mode:        "audit",
			AgentName:   auditDriver,
			TargetURL:   "",
			SourcePath:  absTarget,
			SourceType:  database.InferSourceType(absTarget),
			SessionDir:  parentSessionDir,
			Status:      "running",
			StartedAt:   startedAt,
		}
		if err := repo.CreateAgenticScan(context.Background(), parentRow); err != nil {
			zap.L().Debug("Failed to create parent audit AgenticScan", zap.Error(err))
		}
	}

	streamToConsole := !auditNoStream
	printAuditDispatchBanner(auditDriver, agent.JoinModes(auditModeChain), absTarget, parentSessionDir,
		auditAgentDispatchSummary(auditDriver, settings, authOverride), parentUUID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	plans := orchestrateAuditDrivers(ctx, auditDriver, parentSessionDir, parentUUID, projectUUID,
		absTarget, settings, repo, streamToConsole, authOverride)
	if len(plans) == 0 {
		return fmt.Errorf("no audit drivers ran for --driver=%s", auditDriver)
	}

	var dedupDeleted, dedupGroups int64
	if !auditNoDedup && repo != nil && projectUUID != "" {
		dedupCtx, dedupCancel := context.WithTimeout(context.Background(), agent.AuditDedupTimeout)
		deleted, grouped, dedupErr := repo.DeduplicateFindings(dedupCtx, projectUUID)
		dedupCancel()
		if dedupErr != nil {
			zap.L().Warn("Post-audit findings dedup failed", zap.Error(dedupErr))
		} else {
			dedupDeleted = deleted
			dedupGroups = grouped
		}
	}

	printAuditCombinedSummary(plans, parentSessionDir, dedupDeleted, dedupGroups, repo != nil)

	if repo != nil {
		now := time.Now()
		status := "completed"
		var errMsg string
		for _, p := range plans {
			if p.runErr != nil {
				status = "completed_with_errors"
				if errMsg != "" {
					errMsg += "; "
				}
				errMsg += p.name + ": " + p.runErr.Error()
			}
		}
		totalParsed, totalSaved, _ := driverTotals(plans)
		parentUpdate := &database.AgenticScan{
			UUID:         parentUUID,
			Status:       status,
			ErrorMessage: errMsg,
			CompletedAt:  now,
			DurationMs:   now.Sub(startedAt).Milliseconds(),
			FindingCount: totalParsed,
			SavedCount:   totalSaved,
		}
		if err := repo.UpdateAgenticScan(context.Background(), parentUpdate); err != nil {
			zap.L().Debug("Failed to update parent audit AgenticScan", zap.Error(err))
		}
	}

	allOK, allFailed := driverOutcomes(plans)

	// --stateless: the audit drivers imported the on-disk vigolium-results
	// folder(s) into the throwaway temp DB, so render the self-contained HTML
	// report (and, with --output-dir, a copy of the raw results) now — before
	// the temp DB is discarded by the deferred cleanup.
	if auditStateless {
		emitAuditStatelessArtifacts(context.Background(), db, projectUUID, absTarget, startedAt, plans, allFailed)
	}

	// Skip upload when any driver failed so partial uploads don't get
	// stamped as "complete results".
	if auditUploadResults && allOK {
		uploadAgenticScanResults(settings, projectUUID, parentUUID, parentSessionDir, repo)
	}

	webhook.FireAgenticScan(settings, repo, parentUUID)

	if allFailed {
		return fmt.Errorf("all participating audit drivers failed")
	}

	if globalJSON {
		status := "completed"
		if !allOK {
			status = "completed_with_errors"
		}
		emitAgentScanJSONSummary(repo, projectUUID, parentUUID, status, parentSessionDir)
	}
	return nil
}

// keepSourceResults reports whether <source>/vigolium-results/ should be left
// in the source tree after the run (a session copy is always synced). --keep-raw
// is on by default, so the source-folder copy is retained unless the operator
// passes --clean-raw, which forces the post-run cleanup. Audit-leg only.
func keepSourceResults() bool {
	return auditKeepRaw && !auditCleanRaw
}

// driverOutcomes summarizes the plans into the two boolean flags every
// caller needs after a combined run.
func driverOutcomes(plans []*driverPlan) (allOK, allFailed bool) {
	if len(plans) == 0 {
		return true, false
	}
	allOK, allFailed = true, true
	for _, p := range plans {
		if p.runErr != nil {
			allOK = false
		} else {
			allFailed = false
		}
	}
	return
}

// runAuditDriver runs one child driver and returns its captured outcome.
// Errors land on plan.runErr — the caller continues to the next driver.
//
// authOverride carries any BYOK creds the operator passed via the audit
// CLI flags. It is folded into audit's invocation (via the resolver's
// variadic override) and into the piolium cfg's AuthOverride field, so
// each driver picks it up via its own auth path.
func runAuditDriver(ctx context.Context, name, parentSessionDir, parentUUID, projectUUID, absTarget string,
	settings *config.Settings, repo *database.Repository, streamToConsole bool, authOverride agent.AuthOverride) *driverPlan {

	plan := &driverPlan{
		name:       name,
		sessionDir: filepath.Join(parentSessionDir, name),
	}

	if err := os.MkdirAll(plan.sessionDir, 0o755); err != nil {
		plan.runErr = fmt.Errorf("create %s session dir: %w", name, err)
		return plan
	}

	streamWriter, streamCloser := setupAuditStreamWriter(streamToConsole, plan.sessionDir)
	if streamCloser != nil {
		defer streamCloser()
	}

	switch name {
	case agent.AuditDriverAudit:
		invocation := resolveAuditDriverInvocation(settings.Agent.Olium, settings.Agent.Audit.DefaultAgent, authOverride)
		printAuditDriverBanner(name, string(invocation.Agent), plan.sessionDir)
		cfg := agent.BuildAuditDriverCfg(agent.AuditDriverCfgInput{
			Mode:                  agent.FirstMode(auditDriverModes),
			Modes:                 auditDriverModes,
			SourcePath:            absTarget,
			SessionDir:            plan.sessionDir,
			ProjectUUID:           projectUUID,
			ScanUUID:              globalScanUUID,
			ParentAgenticScanUUID: parentUUID,
			Invocation:            invocation,
			Stream:                true,
			StreamWriter:          streamWriter,
			ShowThinking:          auditShowThinking,
			KeepRaw:               auditKeepRaw,
			KeepSourceOutputDir:   keepSourceResults(),
			AuthOverride:          authOverride,
		})
		plan.runner = agent.NewAuditRunner(cfg, repo)

	case agent.AuditDriverPiolium:
		printAuditDriverBanner(name, "pi", plan.sessionDir)
		// Preflight before piolium kicks in — cheap insurance against
		// audit's results getting stamped "complete" while piolium
		// silently never started.
		if !auditNoPreflight {
			if err := runPiPreflight(auditPiProvider, auditPiModel, auditPreflightTimeout); err != nil {
				plan.runErr = err
				return plan
			}
		}
		cfg := buildPioliumAuditCfg(pioliumCfgInput{
			Mode:            agent.FirstMode(auditPioliumModes),
			Modes:           auditPioliumModes,
			SourcePath:      absTarget,
			SessionDir:      plan.sessionDir,
			ProjectUUID:     projectUUID,
			StreamToConsole: streamToConsole,
			StreamWriter:    streamWriter,
			PiProvider:      auditPiProvider,
			PiModel:         auditPiModel,
			AdditionalArgs:  collectAuditPlmFlags(),
			ScanLimit:       auditPlmScanLimit,
			ScanSince:       auditPlmScanSince,
			AuthOverride:    authOverride,
		})
		cfg.ParentAgenticScanUUID = parentUUID
		plan.runner = agent.NewAuditRunner(cfg, repo)

	default:
		plan.runErr = fmt.Errorf("unknown driver %q", name)
		return plan
	}

	if err := plan.runner.Start(ctx); err != nil {
		plan.runErr = fmt.Errorf("start %s audit: %w", name, err)
		return plan
	}
	plan.runErr = plan.runner.Wait()
	return plan
}

// resolveAuditDriverInvocation resolves audit's agent+auth tuple for
// this run (provider/BYOK precedence), applies the persistent
// agent.audit.default_agent config, then layers the per-run CLI --agent
// override on top — all as pure agent selectors that keep the
// provider-derived auth. Every audit-leg call site in the audit command
// — the dispatch banner, the driver banner, the interactive path, and
// the actual driver run — goes through here so the selection takes
// effect uniformly and what the banner reports is exactly what runs.
//
// Precedence (highest first): --agent flag > --provider flag >
// agent.audit.default_agent > agent.olium.provider-derived > claude.
// default_agent applies only when neither --agent nor --provider pinned
// the agent this run, so an explicit per-run flag always wins over config.
func resolveAuditDriverInvocation(olium config.OliumConfig, defaultAgent string, authOverride agent.AuthOverride) agent.AuditDriverInvocation {
	inv := agent.ResolveAuditDriverInvocation(olium, auditProvider, authOverride)
	if auditAgent == "" && auditProvider == "" {
		agent.ForceAuditDriverAgent(&inv, defaultAgent)
	}
	agent.ForceAuditDriverAgent(&inv, auditAgent)
	return inv
}

// auditDriverAgentLine returns a one-line, human-readable summary of the
// AI agent a given driver will dispatch — so the operator can see at a
// glance whether the audit is running on codex, claude, or pi (and with
// which provider/model) without grepping the harness's own output.
//
// audit's agent (claude|codex) is read back from the *resolved*
// invocation, so it reflects any --provider override and BYOK
// auth-driven agent selection, not just the static olium config.
//
// The returned string is pre-colored (driver name teal, "→" muted, agent
// cyan, trailing detail gray) so the banner can print it verbatim instead
// of flattening the whole row to one color. Rendered shape:
//
//	audit → codex   runs the codex CLI (model from its own config)
func auditDriverAgentLine(name string, settings *config.Settings, authOverride agent.AuthOverride) string {
	orDefault := func(v, fallback string) string {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
		return fallback
	}
	// line assembles "<driver> → <agent>   <detail>" with consistent coloring.
	line := func(driver, agentName, detail string) string {
		return fmt.Sprintf("%s %s %s   %s",
			terminal.HiTeal(driver),
			terminal.Muted("→"),
			terminal.Cyan(agentName),
			terminal.Gray(detail))
	}
	switch name {
	case agent.AuditDriverAudit:
		// audit dispatches the claude/codex CLI directly — it passes
		// only `--agent <claude|codex>` (+ auth), never `--model`. The
		// model is whatever that CLI is configured with, NOT the
		// in-process olium model (which only powers autopilot/swarm/
		// query). Reporting olium's provider/model here was misleading.
		inv := resolveAuditDriverInvocation(settings.Agent.Olium, settings.Agent.Audit.DefaultAgent, authOverride)
		return line("audit", string(inv.Agent), fmt.Sprintf("runs the %s CLI (model from its own config)", inv.Agent))
	case agent.AuditDriverPiolium:
		provider := orDefault(auditPiProvider, "(pi config)")
		model := orDefault(auditPiModel, "(pi config)")
		return line("piolium", "pi", fmt.Sprintf("provider=%s · model=%s", provider, model))
	}
	return ""
}

// auditAgentDispatchSummary composes the dispatch-banner "Agent" entries,
// one per driver the run will touch. For --driver=auto it leads with audit
// (the driver that actually runs first) and notes piolium as the fallback.
// Each entry is rendered on its own line by the banner so a two-driver
// summary stays readable instead of becoming one very long row. Entries are
// already colored by auditDriverAgentLine, so the banner prints them as-is.
func auditAgentDispatchSummary(driver string, settings *config.Settings, authOverride agent.AuthOverride) []string {
	var parts []string
	if agent.DriverIncludesAudit(driver) {
		parts = append(parts, auditDriverAgentLine(agent.AuditDriverAudit, settings, authOverride))
	}
	if agent.DriverIncludesPiolium(driver) {
		line := auditDriverAgentLine(agent.AuditDriverPiolium, settings, authOverride)
		if driver == agent.AuditDriverAuto {
			line += " " + terminal.Muted("(fallback)")
		}
		parts = append(parts, line)
	}
	return parts
}

// auditModeTip returns a one-line, operator-facing hint describing what an
// audit mode does. Rendered under the dispatch banner's Mode line so the
// chosen mode is self-explanatory without running `--list-modes`. Returns
// "" for an unknown mode so the banner simply omits the tip.
func auditModeTip(mode string) string {
	// Keep tips comma/semicolon-delimited (no em-dashes) — printAuditModeTips
	// adds a single "— " separator after the mode name, so a dash here would
	// render as a confusing double dash.
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "lite":
		return "quick triage, lowest cost"
	case "balanced", "scan":
		return "recon + targeted exploitation (recommended)"
	case "deep", "full":
		return "exhaustive multi-phase audit, highest cost"
	case "revisit":
		return "re-open a completed audit to dig deeper"
	case "confirm":
		return "validate findings, prune false positives"
	case "merge":
		return "consolidate findings from previous runs"
	case "diff":
		return "audit only what changed since the last run"
	case "longshot":
		return "deep per-file hunt for elusive bugs (piolium)"
	case "refresh":
		return "rebuild the knowledge base, no full re-audit"
	case "reinvest":
		return "re-investigate previously flagged areas"
	case "mock":
		return "dry run, no real agent calls"
	case "smoke":
		return "minimal pipeline smoke test (piolium)"
	case "status":
		return "print current audit state and exit"
	default:
		return ""
	}
}

// printAuditModeTips renders one short tip line per mode in the (possibly
// chained) mode string, e.g. "deep,confirm" prints a tip for each. Modes
// can't contain commas, so a plain split is safe. Unknown modes are
// silently skipped. The mode name is teal (matching the banner's other
// values) and the description muted, so the tip reads as a sub-note under
// the Mode line.
func printAuditModeTips(w io.Writer, mode string) {
	for _, m := range strings.Split(mode, ",") {
		m = strings.TrimSpace(m)
		if tip := auditModeTip(m); tip != "" {
			_, _ = fmt.Fprintf(w, "    %s %s %s\n",
				terminal.Gray(terminal.SymbolDot),
				terminal.HiTeal(m),
				terminal.Gray("— "+tip))
		}
	}
}

// printAuditDurationHint warns that the recon-heavy modes (balanced, deep)
// can run for a long time on large source trees, so an operator who walks
// away isn't surprised by a multi-hour run. Lighter modes (lite/quick)
// finish quickly enough that the note would just be noise, so only the
// heavy modes trigger it. Split is safe because modes can't contain commas.
func printAuditDurationHint(w io.Writer, mode string) {
	for _, m := range strings.Split(mode, ",") {
		m = strings.TrimSpace(m)
		switch m {
		case "balanced", "deep":
			_, _ = fmt.Fprintf(w, "  %s %s %s\n",
				terminal.Yellow(terminal.SymbolBowtie),
				terminal.HiTeal(m+" mode"),
				terminal.Gray("might take a couple of hours depending on the size of the codebase"))
			return
		}
	}
}

// printAuditDispatchBanner renders the audit startup banner. It mirrors
// printAutopilotBanner's shape (title "<X> Configuration", Purple ◆
// bullets, HiTeal values, home-shortened/Muted paths, and the yellow ◇
// "tail logs" hint) so audit, autopilot, and `vigolium scan` look like
// the same product when an operator switches between them.
func printAuditDispatchBanner(driver, mode, target, parentSessionDir string, agentEntries []string, agenticScanUUID string) {
	w := os.Stderr
	_, _ = fmt.Fprintf(w, "%s %s\n",
		terminal.Green(terminal.SymbolStart),
		terminal.BoldHiBlue("Audit Configuration"))

	_, _ = fmt.Fprintf(w, "  %s Driver: %s | Mode: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(clicommon.ValueOrNone(driver)),
		terminal.Orange(clicommon.ValueOrNone(mode)))

	printAuditModeTips(w, mode)
	printAuditDurationHint(w, mode)

	// Agent: render one driver per line. The first row carries the
	// "Agent:" label and bullet; subsequent rows indent to the same
	// column so a two-driver summary reads as a small block instead of
	// a runaway single line. Entries arrive pre-colored from
	// auditAgentDispatchSummary, so they're printed verbatim.
	for i, entry := range agentEntries {
		if entry == "" {
			continue
		}
		if i == 0 {
			_, _ = fmt.Fprintf(w, "  %s Agent: %s\n",
				terminal.Purple(terminal.SymbolInfo),
				entry)
		} else {
			_, _ = fmt.Fprintf(w, "           %s\n", entry)
		}
	}

	if target != "" {
		_, _ = fmt.Fprintf(w, "  %s Source: %s\n",
			terminal.Purple(terminal.SymbolTarget),
			terminal.HiTeal(terminal.ShortenHome(target)))
	}

	if parentSessionDir != "" {
		_, _ = fmt.Fprintf(w, "  %s Session: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Muted(terminal.ShortenHome(parentSessionDir)))
	}

	if agenticScanUUID != "" {
		_, _ = fmt.Fprintf(w, "  %s %s %s\n",
			terminal.Yellow(terminal.SymbolDiamond),
			terminal.Gray("tail logs with"),
			terminal.HiCyan(fmt.Sprintf("vigolium log %s", agenticScanUUID)))
	}
}

// printAuditDriverBanner marks the start of one driver's phase. Uses the
// orange ▶ "start" symbol — same glyph as the dispatch banner so the
// driver leg reads as a clear section start. agentLabel is the resolved
// coding agent for this leg (claude/codex for the audit driver, "pi" for
// piolium); it is rendered inline so the operator sees exactly which agent
// this leg launched — handy when `--agent` or agent.audit.default_agent
// flipped it away from the provider-derived default. Empty agentLabel
// omits the segment.
func printAuditDriverBanner(driver, agentLabel, sessionDir string) {
	w := os.Stderr
	// Blank line: separates this leg from the dispatch banner above (and from
	// the previous driver's output under --driver=both).
	_, _ = fmt.Fprintln(w)

	label := driver
	if driver == agent.AuditDriverAudit {
		label = "vigolium-audit"
	}
	parts := []string{
		terminal.Orange(terminal.SymbolStart),
		terminal.BoldHiBlue(label),
	}
	if agentLabel != "" {
		parts = append(parts, terminal.Muted("·"), terminal.Cyan("agent="+agentLabel))
	}
	parts = append(parts, terminal.Muted("·"), terminal.Muted(terminal.ShortenHome(sessionDir)))
	_, _ = fmt.Fprintln(w, strings.Join(parts, " "))
}

func printAuditCombinedSummary(plans []*driverPlan, parentSessionDir string, dedupDeleted, dedupGroups int64, persisted bool) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.HiBlue(terminal.SymbolSparkle), terminal.BoldHiBlue("Audit complete"))

	for _, p := range plans {
		fmt.Fprintln(os.Stderr)
		if p.runner == nil {
			fmt.Fprintf(os.Stderr, "%s %s: %s — %v\n",
				terminal.WarningSymbol(),
				terminal.HiTeal(p.name),
				terminal.Red("did not start"),
				p.runErr)
			continue
		}
		status := p.runner.Status()
		stats := p.runner.FindingStats()
		if p.runErr != nil {
			fmt.Fprintf(os.Stderr, "%s %s: finished with error — %v\n",
				terminal.WarningSymbol(), terminal.HiTeal(p.name), p.runErr)
		} else {
			fmt.Fprintf(os.Stderr, "%s %s: %s %d/%d phases\n",
				terminal.SuccessSymbol(),
				terminal.HiTeal(p.name),
				terminal.HiTeal(status.Status),
				status.CompletedPhases, status.TotalPhases)
		}
		printFindingStats(stats, persisted)
		printAuditDriverCostSummary(p.runner.CostSummary())
		fmt.Fprintf(os.Stderr, "  %s Session: %s\n", terminal.InfoSymbol(), terminal.Gray(p.sessionDir))
	}

	if len(plans) > 1 {
		totalParsed, totalSaved, totalCost := driverTotals(plans)
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s Combined: %s parsed, %s saved",
			terminal.Purple(terminal.SymbolBowtie),
			terminal.HiTeal(fmt.Sprintf("%d", totalParsed)),
			terminal.HiTeal(fmt.Sprintf("%d", totalSaved)))
		if totalCost > 0 {
			fmt.Fprintf(os.Stderr, " | cost ~%s",
				terminal.HiTeal(fmt.Sprintf("$%.2f", totalCost)))
		}
		fmt.Fprintln(os.Stderr)
	}

	if dedupGroups > 0 {
		fmt.Fprintf(os.Stderr, "%s Dedup: collapsed %s findings across %s groups\n",
			terminal.Purple(terminal.SymbolDot),
			terminal.HiTeal(fmt.Sprintf("%d", dedupDeleted)),
			terminal.HiTeal(fmt.Sprintf("%d", dedupGroups)))
	}

	fmt.Fprintf(os.Stderr, "%s Session: %s\n", terminal.InfoSymbol(), terminal.Cyan(parentSessionDir))
}

// driverTotals walks the per-driver outcomes once and accumulates the
// stats the parent row + combined banner both need.
func driverTotals(plans []*driverPlan) (parsed, saved int, costUSD float64) {
	for _, p := range plans {
		if p.runner == nil {
			continue
		}
		stats := p.runner.FindingStats()
		parsed += stats.Parsed
		saved += stats.Saved
		costUSD += p.runner.CostSummary().CostUSD
	}
	return
}

// collectAuditPlmFlags renders piolium's --plm-* passthroughs from the
// audit subcommand's globals.
func collectAuditPlmFlags() []string {
	return piolium.PlmFlags{
		ScanLimit:       auditPlmScanLimit,
		ScanSince:       auditPlmScanSince,
		PhaseRetries:    auditPlmPhaseRetries,
		CommandRetries:  auditPlmCommandRetries,
		LongshotLimit:   auditPlmLongshotLimit,
		LongshotTimeout: auditPlmLongshotTimeout,
		LongshotLangs:   auditPlmLongshotLangs,
	}.Args()
}

// ensureAuditDriversFeasible is the pre-clone fail-fast gate. It returns
// an error only when the requested driver cannot possibly run, so we
// don't waste a git clone. It is deliberately quiet on the happy path:
// the per-driver "skipping" warnings are emitted later by
// orchestrateAuditDrivers, when piolium is actually chosen or about to
// run — never eagerly on every audit invocation.
//
// Audit is the embedded vigolium-audit binary (no external CLI lookup);
// availability is bin.Available(). piolium.Diagnose() is only
// consulted when the requested driver actually requires piolium to be
// present up front (--driver=piolium, or a both/auto run that has no
// audit to fall back on).
func ensureAuditDriversFeasible(driver string) error {
	auditAvailable := bin.Available()

	switch driver {
	case agent.AuditDriverAudit:
		if !auditAvailable {
			return fmt.Errorf("vigolium-audit binary not embedded (required for --driver=%s) — run `make build-audit` and rebuild vigolium", driver)
		}
		return nil

	case agent.AuditDriverPiolium:
		// The operator explicitly chose piolium, so a missing runtime is
		// a hard error and the full diagnosis is surfaced here.
		if err := piolium.Diagnose(); err != nil {
			return fmt.Errorf("piolium runtime unavailable (required for --driver=%s): %w", driver, err)
		}
		return nil

	case agent.AuditDriverBoth, agent.AuditDriverAuto:
		// audit present → the run is feasible regardless of piolium, so
		// don't probe (and don't warn about) piolium here.
		if auditAvailable {
			return nil
		}
		// No audit: piolium is the only thing that can run, so it must
		// be present. Probing it here is consistent with "report piolium
		// when it's effectively the chosen driver".
		if err := piolium.Diagnose(); err != nil {
			return fmt.Errorf("neither audit nor piolium is available — run `make build-audit` (for audit) or `pi install git:git@github.com:vigolium/piolium.git` (for piolium)")
		}
		return nil
	}
	return fmt.Errorf("invalid --driver %q", driver)
}

// orchestrateAuditDrivers runs the configured driver(s) and returns the
// per-driver outcomes. It owns the deferred per-driver availability
// messaging: the "piolium runtime unavailable; skipping piolium" warning
// is printed here, only when piolium is actually about to run, so it
// never appears on audit-only or clean --driver=auto runs.
//
//   - audit / piolium  → run that single driver.
//   - both              → run audit (if embedded) then piolium (if its
//     runtime is available), each independently; a failure of one does
//     not abort the other.
//   - auto              → run audit; if it succeeds the audit is done
//     and piolium is never consulted. Only when audit fails (or isn't
//     embedded) does piolium run as a fallback — and only then is its
//     availability checked and any "skipping piolium" message shown.
func orchestrateAuditDrivers(ctx context.Context, driver, parentSessionDir, parentUUID, projectUUID, absTarget string,
	settings *config.Settings, repo *database.Repository, streamToConsole bool, authOverride agent.AuthOverride) []*driverPlan {

	run := func(name string) *driverPlan {
		return runAuditDriver(ctx, name, parentSessionDir, parentUUID, projectUUID,
			absTarget, settings, repo, streamToConsole, authOverride)
	}
	warnPioliumUnavailable := func(err error) {
		fmt.Fprintf(os.Stderr, "%s piolium runtime unavailable (%v); skipping piolium\n",
			terminal.WarningSymbol(), err)
	}
	// For driver=auto/both a chain may contain modes only one driver
	// understands; the other driver's filtered chain is then empty and
	// that leg is skipped with a note rather than running a bogus mode.
	auditHasModes := len(auditDriverModes) > 0
	pioliumHasModes := len(auditPioliumModes) > 0
	noteEmptyChain := func(d string) {
		fmt.Fprintf(os.Stderr, "%s %s: no modes in the chain are supported by %s; skipping %s\n",
			terminal.WarningSymbol(), d, d, d)
	}
	auditAvailable := bin.Available()

	switch driver {
	case agent.AuditDriverAudit:
		return []*driverPlan{run(agent.AuditDriverAudit)}

	case agent.AuditDriverPiolium:
		return []*driverPlan{run(agent.AuditDriverPiolium)}

	case agent.AuditDriverBoth:
		plans := make([]*driverPlan, 0, 2)
		if !auditHasModes {
			noteEmptyChain(agent.AuditDriverAudit)
		} else if auditAvailable {
			plans = append(plans, run(agent.AuditDriverAudit))
		} else {
			fmt.Fprintf(os.Stderr, "%s vigolium-audit binary not embedded; skipping audit (run `make build-audit`)\n",
				terminal.WarningSymbol())
		}
		if !pioliumHasModes {
			noteEmptyChain(agent.AuditDriverPiolium)
		} else if err := piolium.Diagnose(); err == nil {
			plans = append(plans, run(agent.AuditDriverPiolium))
		} else {
			warnPioliumUnavailable(err)
		}
		return plans

	case agent.AuditDriverAuto:
		plans := make([]*driverPlan, 0, 2)
		inv := resolveAuditDriverInvocation(settings.Agent.Olium, settings.Agent.Audit.DefaultAgent, authOverride)
		cliName, cliOK := agent.AuditDriverCLIAvailable(inv.Agent)
		// Preflight: if the coding-agent CLI (claude/codex) the audit
		// driver would drive isn't on PATH, audit can't run — fall back
		// to piolium without launching it. Mid-run audit failures (CLI
		// present but the agent errors during the audit) surface
		// directly; they are not silently retried with piolium.
		switch {
		case auditHasModes && auditAvailable && cliOK:
			plans = append(plans, run(agent.AuditDriverAudit))
			return plans
		case !auditHasModes:
			fmt.Fprintf(os.Stderr, "%s audit: no modes in the chain are supported by audit; falling back to piolium\n",
				terminal.WarningSymbol())
		case !auditAvailable:
			fmt.Fprintf(os.Stderr, "%s vigolium-audit binary not embedded; falling back to piolium (run `make build-audit`)\n",
				terminal.WarningSymbol())
		case !cliOK:
			fmt.Fprintf(os.Stderr, "%s %s CLI not found on PATH; falling back to piolium\n",
				terminal.WarningSymbol(), cliName)
		}
		// Fallback path: piolium is now the effective driver, so this is
		// exactly when its availability should be reported.
		if !pioliumHasModes {
			noteEmptyChain(agent.AuditDriverPiolium)
		} else if err := piolium.Diagnose(); err == nil {
			plans = append(plans, run(agent.AuditDriverPiolium))
		} else {
			warnPioliumUnavailable(err)
		}
		return plans
	}
	return nil
}
