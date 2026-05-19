package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/archon/archonbin"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	archonIntensity     string
	archonMode          string
	archonModes         string
	archonModeChain     []string
	archonListModes     bool
	archonSource        string
	archonProvider      string
	archonAgent         string
	archonNoStream      bool
	archonUploadResults bool
	archonCommitDepth   int
)

var agentArchonCmd = &cobra.Command{
	Use:   "archon",
	Short: "Run archon as a foreground source-code security audit",
	Long: `Run archon, a multi-phase AI security audit, as a foreground process.

Resolves --source (local directory, git URL, gs:// cloud-storage archive,
or local archive — .zip/.tar.gz/.tar.bz2/.tar.xz) and launches the
embedded archon binary against the target source tree. Audit artifacts
land under <session>/archon-audit/ and findings are imported into the
vigolium database. archon dispatches to either Claude or Codex internally
based on the configured olium provider — anthropic-* providers route to
claude, openai-* providers route to codex. Use --archon-provider to
override on a per-run basis.

Audit modes:
  lite       3-phase fast surface scan
  balanced   middle ground between lite and deep (alias: scan)
  deep       full multi-phase audit, highest signal
  revisit    second-pass with anti-anchoring on the latest audit
  reinvest   cross-agent re-verification of CRIT/HIGH findings
  confirm    boot the target and execute PoCs against prior findings
  merge      normalize a pre-merged archon/ dir from external sources
  diff       re-audit only phases affected since a baseline ref
  longshot   hail-mary file-by-file vulnerability hunt
  refresh    auto-route: revisit if a prior audit exists, else fresh deep

Intensity presets (--intensity) bundle the audit mode and clone depth into
a single flag, matching the autopilot/swarm intensity model:
  quick      lite mode, shallow clone (fast triage)
  balanced   balanced mode, shallow clone (default)
  deep       deep mode, full clone history (commit archaeology)

Explicit --mode / --commit-depth always override intensity.`,
	RunE: runAgentArchon,
}

func init() {
	agentCmd.AddCommand(agentArchonCmd)

	f := agentArchonCmd.Flags()
	f.StringVar(&archonIntensity, "intensity", "balanced", "Audit intensity preset: quick, balanced, or deep")
	f.StringVar(&archonMode, "mode", "", "Audit mode override: lite, balanced, deep, revisit, reinvest, confirm, merge, diff, longshot, refresh (overrides --intensity)")
	f.StringVar(&archonModes, "modes", "", "Run a chain of modes back-to-back via archon's native --modes (comma-separated, e.g. deep,refresh,confirm). Overrides --mode/--intensity. archon stops on the first non-complete mode and applies any --max-cost as an aggregate cap.")
	f.BoolVar(&archonListModes, "list-modes", false, "List the available audit modes (phases, time estimate, descriptions) and exit")
	f.StringVar(&archonSource, "source", ".", "Source: local directory, git URL, gs://<project>/<key> archive, or local .zip/.tar.gz")
	f.StringVar(&archonProvider, "archon-provider", "", "Olium provider hint to drive archon's internal --agent: anthropic-* → claude, openai-* → codex (also forwards that provider's BYOK auth). Empty inherits agent.olium.provider. For a pure agent switch without changing auth, prefer --agent.")
	f.StringVar(&archonAgent, "agent", "", "Coding agent: claude or codex. Overrides the agent implied by --archon-provider while keeping its resolved auth.")
	f.BoolVar(&archonNoStream, "no-stream", false, "Don't echo agent output to the console (still written to {session}/runtime.log)")
	f.BoolVar(&archonUploadResults, "upload-results", false, "Upload session bundle to cloud storage after completion (requires storage config)")
	f.IntVar(&archonCommitDepth, "commit-depth", 1, "git clone --depth value when --source is a git URL (default 1; use 0 for full history; overrides --intensity)")
}

func runAgentArchon(cmd *cobra.Command, args []string) error {
	// --list-modes is an early-return info flag: print archon's mode
	// graph and exit before requiring --source / settings / a DB.
	if archonListModes {
		return runListModes(false)
	}

	defer syncLogger()
	defer closeDatabaseOnExit()

	// Resolve --intensity preset; explicit --mode / --modes / --commit-depth override.
	intensity, err := agent.ValidateIntensity(archonIntensity)
	if err != nil {
		return err
	}
	explicitModes := agent.ParseModesCSV(archonModes)
	if cmd != nil {
		changed := map[string]bool{
			"modes":        len(explicitModes) > 0,
			"mode":         cmd.Flags().Changed("mode"),
			"commit-depth": cmd.Flags().Changed("commit-depth"),
		}
		preset := agent.ResolveArchonIntensity(intensity, agent.ArchonIntensityPreset{
			Mode:        archonMode,
			Modes:       explicitModes,
			CommitDepth: archonCommitDepth,
		}, changed)
		archonMode = preset.Mode
		archonModeChain = preset.Modes
		archonCommitDepth = preset.CommitDepth
	} else {
		archonModeChain = []string{archonMode}
	}

	for _, m := range archonModeChain {
		if !agent.IsValidArchonMode(m) {
			return fmt.Errorf("invalid mode %q (must be one of: lite, balanced, deep, revisit, reinvest, confirm, merge, diff, longshot, refresh)", m)
		}
	}
	if archonSource == "" {
		return fmt.Errorf("--source is required (local path or git URL)")
	}

	// --agent is a pure agent selector layered on top of
	// --archon-provider. Reject bad values up front rather than
	// silently falling back to the provider-derived agent.
	archonAgent = strings.TrimSpace(archonAgent)
	if archonAgent != "" && !agent.IsValidArchonAgent(archonAgent) {
		return fmt.Errorf("invalid --agent %q (must be: claude or codex)", archonAgent)
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Probe the embedded archon binary up front so a missing build
	// artifact surfaces as a clear error before we git-clone or
	// download any source.
	if !archonbin.Available() {
		return fmt.Errorf("archon binary not embedded — run `make build-archon` and rebuild vigolium")
	}

	// Resolve archon's --agent + auth from the configured olium
	// provider, with --archon-provider as the per-run override, then
	// apply --agent as a pure agent selector (keeps the resolved auth).
	invocation := agent.ResolveArchonInvocation(settings.Agent.Olium, archonProvider)
	agent.ForceArchonAgent(&invocation, archonAgent)

	// Create the session directory for this run. Pin to --scan-uuid when supplied.
	// The session dir is created before source resolution so git clones and
	// archive extractions can land under {sessionDir}/source/.
	agenticScanUUID := pinnedOrNewUUID(globalScanUUID)
	sessionDir, err := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
	if err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	// Resolve project UUID before source resolution so --project-uuid (or
	// --project-name) can override the project component parsed from a gs://
	// URI — matching the server's startArchonRun behavior.
	projectUUID, _ := resolveProjectUUID()

	// Resolve source: gs:// → download+extract; git URL → clone (with --commit-depth);
	// archive → extract; local path → absolute. Source resolution happens after the
	// session dir is created so cloned/extracted output lands under it.
	resolveSource := archonSource
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
		resolveSource, "", 0, nil, sessionDir,
		agent.WithCloneDepth(archonCommitDepth),
	)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	if absTarget == "" {
		return fmt.Errorf("source path could not be resolved: %s", archonSource)
	}

	// Open DB (optional — findings import is a no-op without it).
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	// Print vigolium-style banner.
	printArchonBanner(agent.JoinModes(archonModeChain), string(invocation.Agent), absTarget, sessionDir)

	// Build the runner config. archon always runs with --json so the
	// streaming goroutine can capture the result event for cost
	// reporting, regardless of whether the user asked to mirror the
	// activity feed to the console.
	streamToConsole := !archonNoStream
	cfg := agent.AuditAgentConfig{
		Mode:             archonMode,
		Modes:            archonModeChain,
		Platform:         agent.PlatformArchonBin,
		SourcePath:       absTarget,
		SessionDir:       sessionDir,
		ProjectUUID:      projectUUID,
		ScanUUID:         globalScanUUID,
		ArchonInvocation: invocation,
		SyncInterval:     30 * time.Second,
		Stream:           true,
	}
	if streamToConsole {
		cfg.StreamWriter = os.Stdout
	}
	// Always persist the stream to {sessionDir}/runtime.log — even in
	// --no-stream mode — so `vigolium log <uuid>` can replay it later.
	if tee, closer := teeToRuntimeLog(cfg.StreamWriter, sessionDir); closer != nil {
		cfg.StreamWriter = tee
		defer func() { _ = closer.Close() }()
	}

	runner := agent.NewAuditAgenticScanner(cfg, repo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start archon-audit: %w", err)
	}

	runErr := runner.Wait()

	// Summary.
	status := runner.Status()
	stats := runner.FindingStats()
	fmt.Fprintln(os.Stderr)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "%s archon-audit finished with error: %v\n",
			terminal.WarningSymbol(), runErr)
	} else {
		fmt.Fprintf(os.Stderr, "%s archon-audit complete — %s %d/%d phases\n",
			terminal.SuccessSymbol(),
			terminal.HiTeal(status.Status),
			status.CompletedPhases, status.TotalPhases)
	}
	printArchonFindingStats(stats, repo != nil)
	printArchonCostSummary(runner.CostSummary())
	fmt.Fprintf(os.Stderr, "%s Session: %s\n", terminal.InfoSymbol(), terminal.Cyan(sessionDir))

	if archonUploadResults && runErr == nil {
		uploadAgenticScanResults(settings, projectUUID, agenticScanUUID, sessionDir, repo)
	}

	webhook.FireAgenticScan(settings, repo, agenticScanUUID)

	return runErr
}

// printArchonCostSummary renders the priced token usage for this run.
// No-op when the cost summary is empty (unsupported backend or missing
// transcript). Backend-specific detail (main+subagents vs just model)
// is encoded in the Note field so this renderer stays backend-agnostic.
func printArchonCostSummary(c agent.ScanCost) {
	if c.IsZero() {
		return
	}
	dot := terminal.Purple(terminal.SymbolInfo)
	fmt.Fprintf(os.Stderr, "%s Cost: %s %s\n",
		dot,
		terminal.HiTeal(fmt.Sprintf("~$%.2f", c.CostUSD)),
		terminal.Gray(c.Note))
}

// printArchonFindingStats writes a severity breakdown of the imported findings
// to stderr. When the repo is nil, only parse counts are shown (no "imported"
// line) since nothing was persisted.
func printArchonFindingStats(stats agent.FindingStats, persisted bool) {
	flag := terminal.Purple(terminal.SymbolFlag)

	if stats.Parsed == 0 {
		fmt.Fprintf(os.Stderr, "%s Findings: %s\n", flag, terminal.Gray("none parsed"))
		return
	}

	fmt.Fprintf(os.Stderr, "%s Findings: %s parsed%s\n",
		flag,
		terminal.HiTeal(fmt.Sprintf("%d", stats.Parsed)),
		archonSavedSuffix(stats, persisted))

	breakdown := stats.SeverityBreakdownString()
	if breakdown != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Gray(terminal.SymbolDot), breakdown)
	}
}

func archonSavedSuffix(stats agent.FindingStats, persisted bool) string {
	if !persisted {
		return terminal.Gray(" (db unavailable — not persisted)")
	}
	if stats.Saved == stats.Parsed {
		return terminal.Gray(fmt.Sprintf(", %d imported", stats.Saved))
	}
	return terminal.Yellow(fmt.Sprintf(", %d/%d imported", stats.Saved, stats.Parsed))
}

func printArchonBanner(mode, agentName, target, sessionDir string) {
	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.Green(terminal.SymbolStart),
		terminal.BoldHiBlue("Archon Audit"))
	fmt.Fprintf(os.Stderr, "  %s Mode: %s | Agent: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiTeal(mode),
		terminal.HiTeal(agentName))
	fmt.Fprintf(os.Stderr, "  %s Source: %s\n",
		terminal.Purple(terminal.SymbolTarget),
		terminal.Orange(target))
	fmt.Fprintf(os.Stderr, "  %s Session: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Gray(sessionDir))
	fmt.Fprintln(os.Stderr)
}
