package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/piolium/pistream"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var (
	pioliumIntensity     string
	pioliumMode          string
	pioliumSource        string
	pioliumNoStream      bool
	pioliumUploadResults bool
	pioliumCommitDepth   int

	pioliumPiProvider string
	pioliumPiModel    string

	pioliumNoPreflight      bool
	pioliumPreflightTimeout time.Duration

	pioliumPlmScanLimit       int
	pioliumPlmScanSince       string
	pioliumPlmPhaseRetries    int
	pioliumPlmCommandRetries  int
	pioliumPlmLongshotLimit   int
	pioliumPlmLongshotTimeout int
	pioliumPlmLongshotLangs   string
)

var agentPioliumCmd = &cobra.Command{
	Use:   "piolium",
	Short: "Run piolium (Pi-native) as a foreground security audit",
	Long: `Run piolium, the Pi-native multi-phase AI security audit, as a foreground process.

Drives the user's installed piolium Pi extension via "pi --mode json -p
/piolium-<mode>". piolium must be registered in ~/.pi/agent/settings.json
(install with: pi install git:git@github.com:vigolium/piolium.git).

Resolves --source (local directory, git URL, gs:// cloud-storage archive,
or local archive — .zip/.tar.gz/.tar.bz2/.tar.xz) and runs the configured
slash command against it. Audit artifacts are synced into the vigolium
agent session directory and findings are imported into the vigolium
database. The on-disk audit-state.json schema is shared with archon, so
archon parsing and reporting tooling apply.

Audit modes:
  lite       quick recon, secrets, fast SAST (4 phases)
  balanced   default audit path with PoCs and report (9 phases)
  deep       full audit (17 phases)
  revisit    anti-anchored second pass over an existing audit
  confirm    confirm existing findings live or with tests
  merge      merge and dedupe result trees from prior runs
  diff       scan changed files since an audited commit
  longshot   hail-mary file-by-file vulnerability hunt

Operator commands (/piolium-status, /piolium-smoke, /piolium-export,
/piolium-learn) are not exposed through this subcommand — invoke them
directly with ` + "`pi -p /piolium-<cmd>`" + ` since they don't produce findings
that need to flow through vigolium's audit pipeline.

Intensity presets (--intensity) bundle the audit mode and clone depth into
a single flag, matching the autopilot/swarm/archon intensity model:
  quick      lite mode, shallow clone (fast triage)
  balanced   balanced mode, shallow clone (default)
  deep       deep mode, full clone history (commit archaeology)

Explicit --mode / --commit-depth always override intensity. Pass --mode
explicitly to invoke audit modes (revisit, confirm, merge, diff,
longshot) that aren't part of the intensity ladder.

To run piolium and archon back-to-back on the same source, use
` + "`vigolium agent audit`" + ` instead — that command dispatches both drivers
(or just one with --driver=piolium|archon) under a single AgenticScan.`,
	RunE: runAgentPiolium,
}

func init() {
	agentCmd.AddCommand(agentPioliumCmd)

	f := agentPioliumCmd.Flags()
	f.StringVar(&pioliumIntensity, "intensity", "balanced", "Audit intensity preset: quick, balanced, or deep")
	f.StringVar(&pioliumMode, "mode", "", "Audit mode override (overrides --intensity): lite, balanced, deep, revisit, confirm, merge, diff, longshot")
	f.StringVar(&pioliumSource, "source", ".", "Source: local directory, git URL, gs://<project>/<key> archive, or local .zip/.tar.gz")
	f.BoolVar(&pioliumNoStream, "no-stream", false, "Don't echo agent output to the console (still written to {session}/runtime.log)")
	f.BoolVar(&pioliumUploadResults, "upload-results", false, "Upload session bundle to cloud storage after completion (requires storage config)")
	f.IntVar(&pioliumCommitDepth, "commit-depth", 1, "git clone --depth value when --source is a git URL (default 1; use 0 for full history; overrides --intensity)")

	f.StringVar(&pioliumPiProvider, "pi-provider", "", "Override pi's defaultProvider for this run (e.g. vertex-anthropic, google-vertex)")
	f.StringVar(&pioliumPiModel, "pi-model", "", "Override pi's defaultModel for this run (e.g. claude-opus-4-6, gemini-3.1-pro)")

	f.BoolVar(&pioliumNoPreflight, "no-preflight", false, "Skip the pre-audit pi roundtrip check (auth + model availability)")
	f.DurationVar(&pioliumPreflightTimeout, "preflight-timeout", piolium.DefaultPreflightTimeout, "Pi preflight timeout (e.g. 30s, 1m)")

	// piolium passthroughs — match the --plm-* flags piolium itself accepts.
	f.IntVar(&pioliumPlmScanLimit, "plm-scan-limit", 0, "[piolium] Cap commit-history scan to N commits (0=piolium default)")
	f.StringVar(&pioliumPlmScanSince, "plm-scan-since", "", `[piolium] Cap commit-history scan to a git --since window (e.g. "60 days ago")`)
	f.IntVar(&pioliumPlmPhaseRetries, "plm-phase-retries", 0, "[piolium] Per-phase retry count (0=piolium default)")
	f.IntVar(&pioliumPlmCommandRetries, "plm-command-retries", 0, "[piolium] Per-command retry count (0=piolium default)")
	f.IntVar(&pioliumPlmLongshotLimit, "plm-longshot-limit", 0, "[piolium] Max files hunted in longshot mode (0=piolium default)")
	f.IntVar(&pioliumPlmLongshotTimeout, "plm-longshot-timeout", 0, "[piolium] Per-file kill timer in longshot mode in ms (0=piolium default)")
	f.StringVar(&pioliumPlmLongshotLangs, "plm-longshot-langs", "", "[piolium] Longshot language allowlist (comma-separated, e.g. python,go)")
}

func runAgentPiolium(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	intensity, err := agent.ValidateIntensity(pioliumIntensity)
	if err != nil {
		return err
	}
	if cmd != nil {
		changed := map[string]bool{
			"mode":         cmd.Flags().Changed("mode"),
			"commit-depth": cmd.Flags().Changed("commit-depth"),
		}
		preset := agent.ResolveArchonIntensity(intensity, agent.ArchonIntensityPreset{
			Mode:        pioliumMode,
			CommitDepth: pioliumCommitDepth,
		}, changed)
		pioliumMode = preset.Mode
		pioliumCommitDepth = preset.CommitDepth
	}

	if !piolium.IsValidMode(pioliumMode) {
		return fmt.Errorf("invalid --mode %q (must be one of: lite, balanced, deep, revisit, confirm, merge, diff, longshot)", pioliumMode)
	}
	if pioliumSource == "" {
		return fmt.Errorf("--source is required (local path or git URL)")
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	if !piolium.IsAvailable() {
		if _, err := exec.LookPath(piolium.Binary); err != nil {
			return fmt.Errorf("pi CLI not found in PATH (install: https://www.npmjs.com/package/@earendil-works/pi-coding-agent)")
		}
		return piolium.EnsurePiInstalled()
	}

	// Session dir must exist before source resolution so git clones and
	// archive extractions can land under {sessionDir}/source/.
	agenticScanUUID := pinnedOrNewUUID(globalScanUUID)
	sessionDir, err := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), agenticScanUUID)
	if err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	projectUUID, _ := resolveProjectUUID()

	resolveSource := pioliumSource
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
		agent.WithCloneDepth(pioliumCommitDepth),
	)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	if absTarget == "" {
		return fmt.Errorf("source path could not be resolved: %s", pioliumSource)
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

	streamToConsole := !pioliumNoStream
	streamWriter, streamCloser := setupAuditStreamWriter(streamToConsole, sessionDir)
	if streamCloser != nil {
		defer streamCloser()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	printPioliumBanner(pioliumMode, absTarget, sessionDir)

	if !pioliumNoPreflight {
		if err := runPiPreflight(pioliumPiProvider, pioliumPiModel, pioliumPreflightTimeout); err != nil {
			return err
		}
	}

	cfg := buildPioliumAuditCfg(pioliumCfgInput{
		Mode:            pioliumMode,
		SourcePath:      absTarget,
		SessionDir:      sessionDir,
		ProjectUUID:     projectUUID,
		StreamToConsole: streamToConsole,
		StreamWriter:    streamWriter,
		PiProvider:      pioliumPiProvider,
		PiModel:         pioliumPiModel,
		AdditionalArgs:  collectPioliumPlmFlags(),
		ScanLimit:       pioliumPlmScanLimit,
		ScanSince:       pioliumPlmScanSince,
	})
	runner := agent.NewAuditAgenticScanner(cfg, repo)

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start piolium audit: %w", err)
	}

	runErr := runner.Wait()
	return finalizeAuditRun(runner, runErr, sessionDir, projectUUID, agenticScanUUID, settings, repo, pioliumUploadResults)
}

// setupAuditStreamWriter combines stdout (when --no-stream is off) with
// a tee to {session}/runtime.log so `vigolium log <uuid>` can replay
// the run regardless of whether anyone was watching live.
func setupAuditStreamWriter(streamToConsole bool, sessionDir string) (io.Writer, func()) {
	var w io.Writer
	if streamToConsole {
		w = os.Stdout
	}
	if tee, closer := teeToRuntimeLog(w, sessionDir); closer != nil {
		return tee, func() { _ = closer.Close() }
	}
	return w, nil
}

// pioliumCfgInput collects everything buildPioliumAuditCfg needs.
// Shared by the standalone `agent piolium` path and the `agent audit`
// driver dispatcher.
type pioliumCfgInput struct {
	Mode            string
	Modes           []string
	SourcePath      string
	SessionDir      string
	ProjectUUID     string
	StreamToConsole bool
	StreamWriter    io.Writer
	PiProvider      string
	PiModel         string
	AdditionalArgs  []string
	ScanLimit       int
	ScanSince       string

	// AuthOverride is the per-run BYOK bundle (api-key / oauth-token /
	// oauth-cred-file) that should be injected as env vars on the pi
	// subprocess (or, for codex cred files, staged at <pi-agent-dir>/auth.json).
	// Empty = inherit ambient pi auth from ~/.pi/agent/settings.json.
	AuthOverride agent.AuthOverride
}

func buildPioliumAuditCfg(in pioliumCfgInput) agent.AuditAgentConfig {
	return agent.AuditAgentConfig{
		Harness:        piolium.DefaultHarness(),
		Mode:           in.Mode,
		Modes:          in.Modes,
		Platform:       agent.PlatformPi,
		SourcePath:     in.SourcePath,
		SessionDir:     in.SessionDir,
		ProjectUUID:    in.ProjectUUID,
		ScanUUID:       globalScanUUID,
		SyncInterval:   agent.DefaultAuditSyncInterval,
		Stream:         in.StreamToConsole,
		AdditionalArgs: in.AdditionalArgs,
		PiProvider:     in.PiProvider,
		PiModel:        in.PiModel,
		StreamDecoder: func(r io.Reader, render io.Writer, raw io.Writer) error {
			return pistream.Stream(r, render, pistream.Options{RawLog: raw})
		},
		CommitScanLimit: in.ScanLimit,
		CommitScanSince: in.ScanSince,
		StreamWriter:    in.StreamWriter,
		AuthOverride:    in.AuthOverride,
	}
}

// finalizeAuditRun prints the operator-facing summary and uploads
// results when configured. Used by both single-driver paths.
func finalizeAuditRun(runner *agent.AuditAgenticScanner, runErr error, sessionDir, projectUUID, agenticScanUUID string, settings *config.Settings, repo *database.Repository, uploadResults bool) error {
	harnessLabel := runner.Harness().Name
	status := runner.Status()
	stats := runner.FindingStats()
	fmt.Fprintln(os.Stderr)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "%s %s audit finished with error: %v\n",
			terminal.WarningSymbol(), harnessLabel, runErr)
	} else {
		fmt.Fprintf(os.Stderr, "%s %s audit complete — %s %d/%d phases\n",
			terminal.SuccessSymbol(),
			harnessLabel,
			terminal.HiTeal(status.Status),
			status.CompletedPhases, status.TotalPhases)
	}
	printArchonFindingStats(stats, repo != nil)
	printArchonCostSummary(runner.CostSummary())
	fmt.Fprintf(os.Stderr, "%s Session: %s\n", terminal.InfoSymbol(), terminal.Cyan(sessionDir))

	if uploadResults && runErr == nil {
		uploadAgenticScanResults(settings, projectUUID, agenticScanUUID, sessionDir, repo)
	}

	webhook.FireAgenticScan(settings, repo, agenticScanUUID)

	return runErr
}

// runPiPreflight surfaces auth and model-availability failures before
// the audit subprocess launches.
func runPiPreflight(provider, model string, timeout time.Duration) error {
	fmt.Fprintf(os.Stderr, "%s Pi preflight check...", terminal.Purple(terminal.SymbolDot))
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	res, err := piolium.Preflight(ctx, piolium.PreflightOptions{
		Provider: provider,
		Model:    model,
		Timeout:  timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, " %s\n", terminal.Red("FAILED"))
		return fmt.Errorf("pi preflight failed: %w (rerun with --no-preflight to bypass)", err)
	}
	fmt.Fprintf(os.Stderr, " %s %s\n", terminal.Green("ok"), terminal.Gray(res.String()))
	fmt.Fprintln(os.Stderr)
	return nil
}

// collectPioliumPlmFlags renders piolium's --plm-* passthroughs from
// the cobra-bound CLI globals.
func collectPioliumPlmFlags() []string {
	return piolium.PlmFlags{
		ScanLimit:       pioliumPlmScanLimit,
		ScanSince:       pioliumPlmScanSince,
		PhaseRetries:    pioliumPlmPhaseRetries,
		CommandRetries:  pioliumPlmCommandRetries,
		LongshotLimit:   pioliumPlmLongshotLimit,
		LongshotTimeout: pioliumPlmLongshotTimeout,
		LongshotLangs:   pioliumPlmLongshotLangs,
	}.Args()
}

func printPioliumBanner(mode, target, sessionDir string) {
	fmt.Fprintf(os.Stderr, "%s %s\n",
		terminal.Green(terminal.SymbolStart),
		terminal.BoldHiBlue("Piolium Audit"))
	fmt.Fprintf(os.Stderr, "  %s Mode: %s | Agent: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiTeal(mode),
		terminal.HiTeal("Piolium"))
	fmt.Fprintf(os.Stderr, "  %s Source: %s\n",
		terminal.Purple(terminal.SymbolTarget),
		terminal.Orange(target))
	fmt.Fprintf(os.Stderr, "  %s Session: %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Gray(sessionDir))
}
