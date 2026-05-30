package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/input/formats/detect"
	"github.com/vigolium/vigolium/pkg/input/formats/openapi"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

var scanOpts = types.DefaultOptions()

// scanReportSharedURL holds the --report-url flag value for native-scan HTML report rendering.
var scanReportSharedURL string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a native scan — deterministic multi-phase vulnerability scanning",
	Long: `Run the native scan pipeline against one or more targets. Phases run in order:
ingestion → discovery → external-harvest → spidering → known-issue-scan → dynamic-assessment → extension.

Use --only / --skip to limit phases, --strategy or --scanning-profile for tuned presets, and --ext / --ext-dir to load custom JavaScript extensions.`,
	RunE: runScanCmd,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	flags := scanCmd.Flags()
	registerInputSourceFlags(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerScanPipelineFlags(flags)
	registerSpecFlags(flags)
	registerNativeScanFlags(flags, true)
}

// allKnownIssueScanSeverities is the full nuclei severity set. A known-issue-scan
// run launched in isolation widens to this so a focused single-phase run is
// exhaustive rather than limited to the balanced default (critical+high).
var allKnownIssueScanSeverities = []string{"critical", "high", "medium", "low", "info"}

// shouldWidenKnownIssueScanSeverities reports whether a known-issue-scan launched
// as the only phase (`vigolium run known-issue-scan` / `--only known-issue-scan`)
// should have its severity filter widened to all levels. Running a single phase on
// its own is normally meant to be an exhaustive sweep, so the balanced default of
// critical+high would silently drop medium/low/info findings. Returns false when
// the user explicitly set --known-issue-scan-severities (their choice wins), when
// any phase other than known-issue-scan is also selected, or when the configured
// set is already empty (= all) or already covers every level.
func shouldWidenKnownIssueScanSeverities(onlyPhase string, severitiesExplicit bool, configured []string) bool {
	if onlyPhase != string(runner.PhaseKnownIssueScan) || severitiesExplicit {
		return false
	}
	if len(configured) == 0 {
		return false // empty = already all severities
	}
	have := make(map[string]bool, len(configured))
	for _, s := range configured {
		have[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, s := range allKnownIssueScanSeverities {
		if !have[s] {
			return true // missing at least one level → widen to all
		}
	}
	return false // already covers every level
}

func runScanCmd(cmd *cobra.Command, args []string) error {
	defer syncLogger()

	// Copy global flags into scan options
	scanOpts.ScanUUID = globalScanUUID
	scanOpts.Modules = resolveModules()
	scanOpts.PassiveModules = []string{"all"}
	scanOpts.Targets = globalTargets
	scanOpts.TargetsFilePath = globalTargetFile
	scanOpts.InputFileMode = globalInputMode
	scanOpts.InputReadTimeout = globalInputReadTimeout
	scanOpts.Timeout = globalTimeout
	scanOpts.Concurrency = globalConcurrency
	scanOpts.MaxPerHost = globalMaxPerHost
	scanOpts.ConcurrencyExplicitlySet = cmd.Flags().Changed("concurrency")
	scanOpts.MaxPerHostExplicitlySet = cmd.Flags().Changed("max-per-host")
	scanOpts.MaxHostError = globalMaxHostError
	scanOpts.MaxFindingsPerModule = globalMaxFindingsPerModule
	scanOpts.Verbose = globalVerbose
	scanOpts.Silent = globalSilent
	scanOpts.Debug = globalDebug
	scanOpts.DumpTraffic = globalDumpTraffic
	scanOpts.JSONOutput = globalJSON
	scanOpts.ProxyURL = globalProxy
	scanOpts.ConfigPath = globalConfig
	scanOpts.Stdin = fileutil.HasStdin()
	scanOpts.OnlyPhase = globalOnly
	scanOpts.SkipPhases = globalSkipPhases
	scanOpts.ScopeOriginMode = globalScopeOrigin
	scanOpts.NoTechFilter = globalNoTechFilter
	scanOpts.OutputFormats = parseFormats(globalFormat)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	scanOpts.ProjectUUID = projectUUID

	if err := reconcileOutputFormats(scanOpts); err != nil {
		return err
	}

	// Stateless mode validation
	scanOpts.Stateless = globalStateless
	scanOpts.SplitByHost = globalSplitByHost
	if scanOpts.Stateless {
		if globalDB != "" {
			return fmt.Errorf("--stateless and --db are mutually exclusive")
		}
		if scanOpts.Output == "" && !scanOpts.Silent {
			fmt.Fprintf(os.Stderr,
				"%s %s: no %s set — scan results will be discarded with the temporary database. "+
					"Pass %s %s and %s %s to persist results.\n",
				terminal.WarnPrefix(),
				terminal.BoldCyan("--stateless"),
				terminal.BoldCyan("-o/--output"),
				terminal.BoldCyan("--output"),
				terminal.BoldYellow("<path>"),
				terminal.BoldCyan("--format"),
				terminal.BoldYellow("jsonl|html"))
		}
	}

	// Load settings from config file
	settings, err := config.LoadSettings(scanOpts.ConfigPath)
	if err != nil {
		if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "%s Config file not found, using defaults\n",
				terminal.Gray(terminal.SymbolPending))
		}
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	if scanOpts.ScopeOriginMode != "" {
		settings.Scope.CLIOriginMode = scanOpts.ScopeOriginMode
	}

	// Override OAST URL if --oast-url flag is set
	if scanOpts.OastURL != "" {
		settings.OAST.OastURL = scanOpts.OastURL
	}

	// Override SQLite path if --db flag is set
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	// Apply --ext / --ext-dir overrides before validation
	applyGlobalExtFlagsToSettings(settings)

	// Validate extensions config
	if err := settings.DynamicAssessment.Extensions.Validate(); err != nil {
		return fmt.Errorf("invalid extensions configuration: %w", err)
	}

	// Validate scanning strategy config
	if err := settings.ScanningStrategy.Validate(); err != nil {
		return fmt.Errorf("invalid scanning strategy configuration: %w", err)
	}

	// Resolve --intensity to scanning profile name.
	if cmd.Flags().Changed("intensity") {
		profileName, resolvedIntensity, intensityErr := agent.ResolveNativeScanIntensity(globalIntensity)
		if intensityErr != nil {
			return intensityErr
		}
		scanOpts.Intensity = resolvedIntensity
		if !cmd.Flags().Changed("scanning-profile") {
			globalScanningProfile = profileName
		}
	}

	// Determine scanning profile: CLI --scanning-profile > config scanning_strategy.scanning_profile
	profileName := globalScanningProfile
	if profileName == "" {
		profileName = settings.ScanningStrategy.ScanningProfile
	}

	// Load and apply scanning profile before strategy resolution
	if profileName != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(profileName)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return fmt.Errorf("failed to load scanning profile %q: %w", profileName, profileErr)
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return fmt.Errorf("failed to apply scanning profile %q: %w", profileName, err)
		}
		scanOpts.ScanningProfile = profileName
		zap.L().Info("Applied scanning profile", zap.String("profile", profileName), zap.String("path", profilePath))
	}

	// Apply scanning strategy as baseline before per-phase overrides
	scanOpts.ScanningStrategy = globalStrategy
	strategyName := globalStrategy
	if strategyName == "" {
		strategyName = settings.ScanningStrategy.DefaultStrategy
	}
	if strategyName != "" {
		phases, ok := settings.ScanningStrategy.GetStrategy(strategyName)
		if !ok {
			return fmt.Errorf("unknown scanning strategy %q; valid names: %v", strategyName, settings.ScanningStrategy.StrategyNames())
		}
		scanOpts.ExternalHarvestEnabled = phases.ExternalHarvesting
		scanOpts.DiscoverEnabled = phases.Discovery
		scanOpts.SpideringEnabled = phases.Spidering
		scanOpts.KnownIssueScanEnabled = phases.KnownIssueScan
		if !phases.DynamicAssessment {
			scanOpts.SkipDynamicAssessment = true
		}
		zap.L().Debug("Applied scanning strategy", zap.String("strategy", strategyName))
	}

	// Resolve heuristics check level
	// Precedence: --skip-heuristics > --heuristics-check > config default > "basic"
	scanOpts.HeuristicsCheck = "basic"
	if settings.ScanningStrategy.HeuristicsCheck != "" {
		scanOpts.HeuristicsCheck = settings.ScanningStrategy.HeuristicsCheck
	}
	if globalHeuristicsCheck != "" {
		scanOpts.HeuristicsCheck = globalHeuristicsCheck
	}
	if globalSkipHeuristics {
		scanOpts.HeuristicsCheck = "none"
	}

	if err := runner.ApplyNativePhaseSelection(scanOpts, func() {
		settings.DynamicAssessment.Extensions.Enabled = true
	}); err != nil {
		return err
	}
	if scanOpts.OnlyPhase != "" {
		zap.L().Info("Phase isolation active", zap.String("only", scanOpts.OnlyPhase))
	}
	if len(scanOpts.SkipPhases) > 0 {
		zap.L().Info("Phases skipped", zap.Strings("skip", scanOpts.SkipPhases))
	}

	// Validate HTML output format constraints
	if scanOpts.HasFormat("html") {
		if scanOpts.Output == "" {
			return fmt.Errorf("--format html requires -o/--output to specify the report file path")
		}
		if phases := runner.OnlyPhaseSet(scanOpts.OnlyPhase); len(phases) > 0 {
			for p := range phases {
				if p != "discovery" && p != "spidering" {
					return fmt.Errorf("--format html is only supported for discovery and spidering phases")
				}
			}
		}
	}

	for _, f := range []string{"report", "pdf"} {
		if scanOpts.HasFormat(f) && scanOpts.Output == "" {
			return fmt.Errorf("--format %s requires -o/--output to specify the report file path", f)
		}
	}

	// Multi-format requires -o/--output for file-based formats
	if len(scanOpts.OutputFormats) > 1 && scanOpts.Output == "" {
		return fmt.Errorf("multiple --format values require -o/--output to specify the base output path")
	}

	// Override scanning_pace.max_duration if --scanning-max-duration flag is set.
	// This value plays two roles: it seeds the per-phase base (each phase scales
	// it by its duration_factor) AND caps total wall-clock time for the whole
	// scan via Options.ScanMaxDuration, so the per-phase factors distribute time
	// within the total budget rather than stacking sequentially past it.
	if cmd.Flags().Changed("scanning-max-duration") && globalScanningMaxDuration > 0 {
		settings.ScanningPace.MaxDuration = globalScanningMaxDuration.String()
		scanOpts.ScanMaxDuration = globalScanningMaxDuration
	}

	// Validate and apply scanning_pace centralized speed control
	if err := settings.ScanningPace.Validate(); err != nil {
		return fmt.Errorf("invalid scanning_pace configuration: %w", err)
	}

	// Apply scanning_pace common values (precedence 4 — lowest after built-in defaults)
	pace := &settings.ScanningPace
	if !scanOpts.ConcurrencyExplicitlySet && pace.Concurrency > 0 {
		scanOpts.Concurrency = pace.Concurrency
	}
	if !scanOpts.MaxPerHostExplicitlySet && pace.MaxPerHost > 0 {
		scanOpts.MaxPerHost = pace.MaxPerHost
	}

	// Apply scanning_pace.discovery.max_duration (precedence 3) to scanOpts
	discoveryPace := pace.ResolvePhase("discovery")
	if !cmd.Flags().Changed("discover-max-time") && discoveryPace.MaxDuration > 0 {
		scanOpts.DiscoverMaxDuration = discoveryPace.MaxDuration
	}

	// Apply scanning_pace.spidering.max_duration to scanOpts
	spideringPace := pace.ResolvePhase("spidering")
	if !cmd.Flags().Changed("spider-max-time") && spideringPace.MaxDuration > 0 {
		scanOpts.SpideringMaxDuration = spideringPace.MaxDuration
	}

	// Validate per-phase configs when enabled (strategy + CLI flags are the only sources)
	if scanOpts.DiscoverEnabled {
		if err := settings.Discovery.Validate(); err != nil {
			return fmt.Errorf("invalid discovery configuration: %w", err)
		}
	}
	if scanOpts.KnownIssueScanEnabled {
		// Apply CLI overrides for KnownIssueScan config
		if cmd.Flags().Changed("known-issue-scan-tags") {
			settings.KnownIssueScan.Tags = scanOpts.KnownIssueScanTags
		}
		if cmd.Flags().Changed("known-issue-scan-exclude-tags") {
			settings.KnownIssueScan.ExcludeTags = scanOpts.KnownIssueScanExcludeTags
		}
		if cmd.Flags().Changed("known-issue-scan-severities") {
			settings.KnownIssueScan.Severities = scanOpts.KnownIssueScanSeverities
		}
		// When known-issue-scan is the only phase requested, treat it as a focused
		// full scan and widen severities to all levels (unless the user pinned them
		// with --known-issue-scan-severities). The balanced default ships
		// critical+high, which would silently drop medium/low/info on an isolated run.
		if shouldWidenKnownIssueScanSeverities(scanOpts.OnlyPhase, cmd.Flags().Changed("known-issue-scan-severities"), settings.KnownIssueScan.Severities) {
			prev := strings.Join(settings.KnownIssueScan.Severities, ",")
			settings.KnownIssueScan.Severities = append([]string(nil), allKnownIssueScanSeverities...)
			if !scanOpts.Silent {
				fmt.Fprintf(os.Stderr, "  %s %s\n",
					terminal.TipPrefix(),
					terminal.Gray(fmt.Sprintf("running only known-issue-scan — adjusted known_issue_scan.severities from %s to all severities (%s) for this scan",
						prev, strings.Join(allKnownIssueScanSeverities, ","))))
			}
		}
		if cmd.Flags().Changed("known-issue-scan-templates-dir") {
			settings.KnownIssueScan.TemplatesDir = scanOpts.KnownIssueScanTemplatesDir
		}
		if err := settings.KnownIssueScan.Validate(); err != nil {
			return fmt.Errorf("invalid known-issue-scan configuration: %w", err)
		}
	}
	if scanOpts.SpideringEnabled {
		// Apply CLI overrides for spidering config
		if cmd.Flags().Changed("browser-engine") {
			settings.Spidering.BrowserEngine = scanOpts.SpideringBrowserEngine
		}
		if cmd.Flags().Changed("browsers") {
			settings.Spidering.BrowserCount = scanOpts.SpideringBrowserCount
		}
		if cmd.Flags().Changed("headless") {
			settings.Spidering.Headless = scanOpts.SpideringHeadless
		}
		// --headed is sugar for --headless=false and wins ties: a user who
		// explicitly asks to see the window gets a visible browser even if
		// --headless was also passed.
		if cmd.Flags().Changed("headed") && scanOpts.SpideringHeaded {
			settings.Spidering.Headless = false
		}
		if cmd.Flags().Changed("no-cdp") {
			settings.Spidering.NoCDP = scanOpts.SpideringNoCDP
		}
		if cmd.Flags().Changed("no-forms") {
			settings.Spidering.NoForms = scanOpts.SpideringNoForms
		}
		if err := settings.Spidering.Validate(); err != nil {
			return fmt.Errorf("invalid spidering configuration: %w", err)
		}
	}
	if scanOpts.ExternalHarvestEnabled {
		if len(settings.ExternalHarvester.Sources) == 0 {
			defaults := config.DefaultExternalHarvesterConfig()
			settings.ExternalHarvester.Sources = defaults.Sources
		}
		if err := settings.ExternalHarvester.Validate(); err != nil {
			return fmt.Errorf("invalid external harvester configuration: %w", err)
		}
	}

	// A target file that yields no targets is a misconfiguration in every mode;
	// fail loudly rather than running a zero-target scan that reports "completed".
	// (The --split-by-host path re-checks this in runStatelessTargetFile; the
	// shared fall-through below otherwise has no such guard.)
	if scanOpts.TargetsFilePath != "" {
		fileTargets, terr := readTargetFileLines(scanOpts.TargetsFilePath)
		if terr != nil {
			return terr
		}
		if len(fileTargets) == 0 {
			return fmt.Errorf("target file %q contains no targets", scanOpts.TargetsFilePath)
		}
	}

	// Multi-target stateless with --split-by-host: iterate per line with a fresh
	// temp DB each time, writing one per-host output file per target. Without the
	// flag, fall through to a single shared pass so the whole target file scans
	// into one temp DB and exports to one unified output file (all formats).
	if scanOpts.Stateless && scanOpts.TargetsFilePath != "" && scanOpts.SplitByHost {
		return runStatelessTargetFile(cmd, settings, strategyName)
	}

	return executeNativeScan(cmd, settings, strategyName)
}

// executeNativeScan runs one full native scan pass against the current
// scanOpts. In stateless mode it allocates a fresh temporary SQLite database
// and tears it down on return so callers can invoke it once per target.
func executeNativeScan(cmd *cobra.Command, settings *config.Settings, strategyName string) (err error) {
	// Wall-clock anchor for the whole scan pass, surfaced in the completion
	// summary. Captured before DB setup so it reflects total time, not just the
	// scanning legs.
	scanStart := time.Now()

	// Stateless mode: create a temporary SQLite database for this run only.
	var statelessDBPath string
	if scanOpts.Stateless {
		tmpFile, tmpErr := os.CreateTemp("", "vigolium-stateless-*.sqlite")
		if tmpErr != nil {
			return fmt.Errorf("failed to create temporary database: %w", tmpErr)
		}
		statelessDBPath = tmpFile.Name()
		_ = tmpFile.Close()
		defer func() {
			_ = os.Remove(statelessDBPath)
			_ = os.Remove(statelessDBPath + "-wal")
			_ = os.Remove(statelessDBPath + "-shm")
		}()

		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = statelessDBPath
	}

	if err := settings.Database.Validate(); err != nil {
		return fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database connection: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create database schema: %w", err)
	}

	repo := database.NewRepository(db)
	zap.L().Debug("Database initialized successfully",
		zap.String("driver", db.Driver()))

	// Stateless + -o + default console format: capture the full verbose
	// console session (banner, scan summary, phase progress, result lines)
	// into the output file as a faithful transcript, instead of the minimal
	// per-record DB export. Started before printScanSummary so the banner is
	// included. Other --format values keep the post-scan DB export below.
	transcriptActive := scanOpts.Stateless && scanOpts.Output != "" &&
		!scanOpts.Silent && !globalJSON && !globalCIOutput &&
		len(scanOpts.OutputFormats) == 1 && scanOpts.OutputFormats[0] == "console"
	if transcriptActive {
		transcriptPath := scanOpts.Output
		tc, tErr := startTranscriptCapture(transcriptPath)
		if tErr != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to start transcript capture (%v); falling back to record export\n",
				terminal.WarnPrefix(), tErr)
			transcriptActive = false
		} else {
			defer func() {
				tc.Stop()
				fmt.Fprintf(os.Stderr, "%s Transcript written to %s\n",
					terminal.InfoSymbol(), terminal.Cyan(transcriptPath))
			}()
		}
	}

	// Pin the scan UUID before the banner so the config summary can show it and
	// the runner reuses the same identifier instead of minting its own.
	scanOpts.ScanUUID = pinnedOrNewUUID(scanOpts.ScanUUID)
	// Print scan summary banner (after DB init so we can show HTTP record count)
	printScanSummary(scanOpts, settings, strategyName, repo)
	scanOpts.ScanConfigPrinted = true

	// For stateless mode with --output: suppress StandardWriter's live file
	// output and export the full database post-scan. This covers console
	// (default), jsonl, and report formats so -o always produces a populated
	// file even when the phase only ingests HTTP records (e.g. discovery) and
	// emits no findings for StandardWriter to write.
	var statelessOutputPath string
	if scanOpts.Stateless && scanOpts.Output != "" {
		statelessOutputPath = scanOpts.Output
		savedOutput := scanOpts.Output
		scanOpts.Output = "" // prevent StandardWriter from creating the output file
		defer func() { scanOpts.Output = savedOutput }()
	}
	// Defer stateless export so all exit paths are covered automatically. When
	// a transcript is being captured, skip the console export so it does not
	// truncate and clobber the transcript file at the same path.
	defer func() { finishStatelessExport(db, scanOpts, statelessOutputPath, transcriptActive) }()
	// Persisted (non-stateless) --format jsonl emits the same project-scoped
	// unified envelope post-scan instead of StandardWriter's live nuclei stream
	// (suppressed via DeferredJSONLExport). No-ops for stateless and CI runs.
	defer func() {
		// Skip the deferred jsonl envelope when it would be misleading or
		// redundant:
		//  - stateless WITH -o: finishStatelessExport already materializes every
		//    format to the file, and scanOpts.Output is temporarily blanked here,
		//    so finishScanJSONLExport can't detect this case itself — without this
		//    guard it would also stream the envelope to stdout (double output).
		//  - a hard-failed persisted scan: don't write a success-looking
		//    file/stream of stale or partial project data (mirrors the skipped
		//    "completed" banner). Stateless is exempt — its temp DB is discarded
		//    after the run, so the stdout stream is the only chance to surface
		//    whatever was found.
		if scanOpts.Stateless && statelessOutputPath != "" {
			return
		}
		if err != nil && !scanOpts.Stateless {
			return
		}
		finishScanJSONLExport(db, scanOpts)
	}()

	// If -i was explicitly provided, use two-phase ingest-then-scan
	hasInputFile := globalInput != "" && globalInput != "-"
	if hasInputFile {
		return runScanWithIngest(settings, db, repo, scanStart)
	}

	// If no targets/input/stdin, fall back to scanning DB records
	hasTargets := len(scanOpts.Targets) > 0
	hasTargetFile := scanOpts.TargetsFilePath != ""
	hasStdin := scanOpts.Stdin
	if !hasTargets && !hasTargetFile && !hasStdin {
		return runDBScan(settings, db, repo, scanStart)
	}

	// Smart stdin detection: if stdin is present and -I was not explicitly set,
	// peek at the content to detect raw HTTP or curl format
	if hasStdin && !cmd.Flags().Changed("input-mode") {
		raw, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return fmt.Errorf("failed to read stdin: %w", readErr)
		}
		content := strings.TrimSpace(string(raw))
		if content != "" {
			detected := detect.DetectStdinFormat(content)
			if detected != detect.FormatURLs {
				// Raw HTTP or curl — parse eagerly and use SliceSource
				items, parseErr := detect.ParseStdinContent(content, detected)
				if parseErr != nil {
					return fmt.Errorf("failed to parse stdin as %s: %w", detected, parseErr)
				}
				inputSrc := source.NewSliceSource(items, scanOpts.Modules)
				scanOpts.Stdin = false

				scanRunner, runnerErr := runner.NewWithInputSource(scanOpts, inputSrc)
				if runnerErr != nil {
					return fmt.Errorf("failed to create scan runner: %w", runnerErr)
				}

				scanRunner.SetSettings(settings)
				if repo != nil {
					scanRunner.SetRepository(repo)
				}

				setupScanSignalHandler(scanRunner)

				// Close before reporting (so any flush lands in the DB the reports
				// read) — matching the main runner.New path below.
				scanErr := scanRunner.RunNativeScan()
				scanRunner.Close()
				if scanErr != nil {
					return scanErr
				}
				reportNativeScanSuccess(db, settings, repo, scanStart)
				return nil
			}
		}
		// URLs detected — fall through to existing runner.New() which handles stdin streaming.
		// However, we already consumed stdin, so we need to pass the content as targets instead.
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				scanOpts.Targets = append(scanOpts.Targets, line)
			}
		}
		scanOpts.Stdin = false
	}

	scanRunner, err := runner.New(scanOpts)
	if err != nil {
		zap.L().Fatal("Could not create runner", zap.Error(err))
	}
	if scanRunner == nil {
		return nil
	}

	// Set settings and repository on runner
	scanRunner.SetSettings(settings)
	if repo != nil {
		scanRunner.SetRepository(repo)
	}

	setupScanSignalHandler(scanRunner)

	scanErr := scanRunner.RunNativeScan()
	scanRunner.Close()
	// A failed scan must abort visibly: returning the error makes cobra print it
	// (it's an ErrorLevel-and-above world by default, so the old INFO log was
	// invisible without --verbose) and exit non-zero, and skips the "completed"
	// banner below — which would otherwise claim success over stale/partial DB
	// data (e.g. a session-init failure where no scanning ran at all).
	if scanErr != nil {
		return scanErr
	}

	reportNativeScanSuccess(db, settings, repo, scanStart)
	return nil
}

// reportNativeScanSuccess runs the post-scan tail shared by every native-scan
// entry point: report-file generation, result upload, and the completion
// summary banner. It is invoked only when RunNativeScan returned no error — a
// failed scan returns its error to the caller instead, so this success banner
// never paints over a scan that didn't actually run. A scan curtailed by
// --scanning-max-duration returns nil (graceful), so time-boxed partial scans
// still reach this path and keep their reports.
func reportNativeScanSuccess(db *database.DB, settings *config.Settings, repo *database.Repository, scanStart time.Time) {
	maybeGenerateReports(db, scanOpts)
	uploadNativeScanResults(settings, scanOpts, repo)
	if !scanOpts.Silent {
		fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.Aqua(terminal.SymbolSparkle), terminal.BoldAqua("Native scan completed"))
		printScanCompletionSummary(repo, time.Since(scanStart))
	}
}

// runStatelessTargetFile iterates over each non-blank line in
// scanOpts.TargetsFilePath, allocating an isolated temporary database per
// target and tearing it down before moving on. When --output is provided, the
// output path is suffixed with the target's hostname so per-target results do
// not overwrite each other. This is the --split-by-host path; without that flag
// runScanCmd instead runs a single shared pass over the whole target file for a
// unified output file.
func runStatelessTargetFile(cmd *cobra.Command, settings *config.Settings, strategyName string) error {
	targets, err := readTargetFileLines(scanOpts.TargetsFilePath)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("target file %q contains no targets", scanOpts.TargetsFilePath)
	}

	origTargets := append([]string(nil), scanOpts.Targets...)
	origFile := scanOpts.TargetsFilePath
	origOutput := scanOpts.Output
	origPrinted := scanOpts.ScanConfigPrinted
	scanOpts.TargetsFilePath = ""
	defer func() {
		scanOpts.Targets = origTargets
		scanOpts.TargetsFilePath = origFile
		scanOpts.Output = origOutput
		scanOpts.ScanConfigPrinted = origPrinted
	}()

	multi := len(targets) > 1
	for i, target := range targets {
		scanOpts.Targets = []string{target}
		// Force the scan summary banner to print per target.
		scanOpts.ScanConfigPrinted = false
		if multi && origOutput != "" {
			scanOpts.Output = perTargetOutputPath(origOutput, target, i)
		} else {
			scanOpts.Output = origOutput
		}

		if !scanOpts.Silent {
			fmt.Fprintf(os.Stderr, "\n%s %s %s\n",
				terminal.Purple(terminal.SymbolTarget),
				terminal.BoldHiBlue(fmt.Sprintf("[%d/%d]", i+1, len(targets))),
				terminal.HiCyan(target))
		}

		if scanErr := executeNativeScan(cmd, settings, strategyName); scanErr != nil {
			zap.L().Error("Stateless target scan failed",
				zap.String("target", target),
				zap.Error(scanErr))
			fmt.Fprintf(os.Stderr, "%s scan for %s failed: %v\n",
				terminal.WarnPrefix(), terminal.HiCyan(target), scanErr)
			// Continue with remaining targets instead of aborting the batch.
		}
	}

	return nil
}

// readTargetFileLines reads a target file (one URL or address per line),
// trimming whitespace and skipping blank lines and `#` comments.
func readTargetFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open target file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read target file %q: %w", path, err)
	}
	return lines, nil
}

// perTargetOutputPath returns a target-specific variant of basePath so that
// per-target stateless exports do not clobber each other. The sanitized
// host[:port] is inserted before the format extension; if the target can't be
// parsed as a URL or yields an empty host, the iteration index is used.
func perTargetOutputPath(basePath, target string, idx int) string {
	stripped := types.StripFormatExtension(basePath)
	suffix := perTargetSuffix(target, idx)
	rest := strings.TrimPrefix(basePath, stripped)
	return stripped + "-" + suffix + rest
}

// perTargetSuffix derives a filesystem-safe suffix from a target URL/host.
func perTargetSuffix(target string, idx int) string {
	candidate := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		candidate = u.Host
	}
	candidate = strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_",
	).Replace(candidate)
	candidate = strings.Trim(candidate, "._")
	if candidate == "" {
		return fmt.Sprintf("%03d", idx+1)
	}
	return candidate
}

// runScanWithIngest delegates to the Runner's 3-phase pipeline when -i is provided.
// The Runner's Phase 1 ingests the input file, Phase 2 runs KnownIssueScan if enabled,
// and Phase 3 scans from DB with all modules.
func runScanWithIngest(settings *config.Settings, db *database.DB, repo *database.Repository, scanStart time.Time) error {
	// Auto-detect format from file extension
	inputFormat := globalInputMode
	if inputFormat == "urls" {
		if detected := detectInputFormat(globalInput); detected != "" {
			inputFormat = detected
			zap.L().Info("Auto-detected input format", zap.String("format", inputFormat))
		}
	}

	// OpenAPI defaults: auto-enable UseSpecServers when no -t given
	useSpecServers := globalSpecURL
	if (inputFormat == "openapi" || inputFormat == "swagger") &&
		len(globalTargets) == 0 && !useSpecServers {
		useSpecServers = true
		zap.L().Info("Auto-enabled --spec-url (no -t provided)")
	}

	// Create InputSource from the input file
	inputSource, err := source.NewInputSource(source.SourceConfig{
		Targets:       globalTargets,
		FilePath:      globalInput,
		Format:        inputFormat,
		BufferSize:    100,
		EnableModules: scanOpts.Modules,
	})
	if err != nil {
		return fmt.Errorf("failed to create input source: %w", err)
	}

	// Configure OpenAPI options if applicable
	if inputFormat == "openapi" || inputFormat == "swagger" {
		if fs, ok := inputSource.(*source.FileSource); ok {
			if openapiFormat, ok := fs.Format().(*openapi.Format); ok {
				var targetURL string
				if len(globalTargets) > 0 {
					targetURL = globalTargets[0]
				}
				openapiFormat.SetOpenAPIOptions(openapi.Options{
					BaseURL:              targetURL,
					UseSpecServers:       useSpecServers,
					Headers:              ingestParseHeaders(globalSpecHeader),
					Variables:            ingestParseVariables(globalSpecVar),
					DefaultFallbackValue: globalSpecDefault,
				})
			}
		}
	}

	// Create Runner with the input source — RunNativeScan handles all 3 phases
	scanRunner, err := runner.NewWithInputSource(scanOpts, inputSource)
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	setupScanSignalHandler(scanRunner)

	// A failed scan must abort visibly (return non-zero, skip the success
	// banner) rather than logging at INFO and claiming completion — matching the
	// direct-target path. See reportNativeScanSuccess.
	if err := scanRunner.RunNativeScan(); err != nil {
		return err
	}

	reportNativeScanSuccess(db, settings, repo, scanStart)
	return nil
}

// runDBScan scans records already in the database (no explicit targets).
// Delegates to RunNativeScan(): Phase 1 is a no-op (empty source),
// Phase 2 runs KnownIssueScan if enabled, Phase 3 reads existing DB records.
func runDBScan(settings *config.Settings, db *database.DB, repo *database.Repository, scanStart time.Time) error {
	// Create Runner with an empty input source — Phase 1 becomes a no-op
	scanRunner, err := runner.NewWithInputSource(scanOpts, &emptySource{})
	if err != nil {
		return fmt.Errorf("failed to create scan runner: %w", err)
	}
	defer scanRunner.Close()

	scanRunner.SetSettings(settings)
	scanRunner.SetRepository(repo)

	setupScanSignalHandler(scanRunner)

	// A failed scan must abort visibly (return non-zero, skip the success
	// banner) rather than logging at INFO and claiming completion — matching the
	// direct-target path. See reportNativeScanSuccess.
	if err := scanRunner.RunNativeScan(); err != nil {
		return err
	}

	reportNativeScanSuccess(db, settings, repo, scanStart)
	return nil
}

// emptySource is an InputSource that immediately returns io.EOF.
// Used when no external input is provided (DB-only scan mode).
type emptySource struct{}

func (e *emptySource) Next(_ context.Context) (*work.WorkItem, error) { return nil, io.EOF }
func (e *emptySource) Close() error                                   { return nil }

// generateReportFromDB queries data from the database and generates a report at
// the specified output path using the given generator function. projectUUID
// scopes the query: "" exports the whole DB (stateless temp DB), a non-empty
// value scopes to one project so a persisted report matches the sibling jsonl
// export and never leaks other projects' findings.
func generateReportFromDB(ctx context.Context, db *database.DB, outputPath string, omitResponse bool, projectUUID string, generate func([]any, string, output.HTMLReportMeta) error) error {
	items, err := queryExportData(ctx, db, omitResponse, projectUUID)
	if err != nil {
		return err
	}
	autoTarget, autoDuration := computeReportMeta(ctx, db)
	meta := output.HTMLReportMeta{
		Title:           "Vigolium Scan Report",
		Version:         getVersion(),
		ScanDuration:    autoDuration,
		ScanTarget:      autoTarget,
		ReportSharedURL: scanReportSharedURL,
	}
	return generate(items, outputPath, meta)
}

// parseFormats splits a comma-separated format string, defaulting to "console".
func parseFormats(raw string) []string {
	parts := strings.Split(raw, ",")
	formats := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			formats = append(formats, p)
		}
	}
	if len(formats) == 0 {
		return []string{"console"}
	}
	return formats
}

// reconcileOutputFormats applies --json and --ci-output-format overrides to
// OutputFormats and validates the result. Shared by scan and scan-url commands.
func reconcileOutputFormats(opts *types.Options) error {
	if globalJSON && len(opts.OutputFormats) == 1 && opts.OutputFormats[0] == "console" {
		opts.OutputFormats = []string{"jsonl"}
	}
	if opts.HasFormat("jsonl") {
		opts.JSONOutput = true
	}
	if globalCIOutput {
		opts.CIOutput = true
		opts.OutputFormats = []string{"jsonl"}
		opts.JSONOutput = true
		opts.Silent = true
	}
	for _, f := range opts.OutputFormats {
		switch f {
		case "console", "jsonl", "html", "report", "pdf":
		default:
			return fmt.Errorf("invalid --format value %q; valid formats: console, jsonl, html, report, pdf", f)
		}
	}
	// Route jsonl through the post-scan project-scoped envelope export so the
	// scan output matches `vigolium export`/stateless. CI output keeps its own
	// findings-only emitter (see outputScanResult), so leave it on the legacy
	// live path.
	opts.DeferredJSONLExport = opts.HasFormat("jsonl") && !opts.CIOutput
	return nil
}

// reportFormatEntry maps a --format value to its generator and display label.
type reportFormatEntry struct {
	format    string
	label     string
	generate  func([]any, string, output.HTMLReportMeta) error
	beforeMsg string // optional stderr message before generation
}

var reportFormats = []reportFormatEntry{
	{"html", "HTML report", output.GenerateHTMLReport, ""},
	{"report", "Document report", output.GenerateDocumentReport, ""},
	{"pdf", "PDF report", output.GeneratePDFReport, "Generating PDF report (headless Chrome)..."},
}

// maybeGenerateReports generates all requested file-based reports post-scan.
func maybeGenerateReports(db *database.DB, opts *types.Options) {
	if opts.Output == "" {
		return
	}
	ctx := context.Background()
	for _, rf := range reportFormats {
		if !opts.HasFormat(rf.format) {
			continue
		}
		outPath := opts.OutputPathForFormat(rf.format)
		if rf.beforeMsg != "" {
			fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
		}
		if err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, exportProjectScope(opts), rf.generate); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to generate %s: %v\n", terminal.ErrorPrefix(), rf.label, err)
		} else {
			fmt.Fprintf(os.Stderr, "%s %s: %s\n", terminal.InfoSymbol(), rf.label, terminal.Cyan(outPath))
		}
	}
}

// finishStatelessExport writes the full database export to the output file(s)
// when running in stateless mode. StandardWriter's live file output is
// suppressed in stateless mode, so every requested format (console, jsonl,
// html, report, pdf) is materialized here from the database.
func finishStatelessExport(db *database.DB, opts *types.Options, outputPath string, skipConsole bool) {
	if !opts.Stateless || outputPath == "" {
		return
	}

	ctx := context.Background()
	basePath := types.StripFormatExtension(outputPath)

	for _, format := range opts.OutputFormats {
		outPath := types.FormatOutputPath(basePath, format)
		switch format {
		case "console":
			if skipConsole {
				// A transcript was captured to this path; do not overwrite it.
				continue
			}
			exportStatelessConsole(ctx, db, outPath, opts.OmitResponse)
		case "jsonl":
			exportStatelessJSONL(ctx, db, opts, outPath)
		default:
			for _, rf := range reportFormats {
				if rf.format != format {
					continue
				}
				if rf.beforeMsg != "" {
					fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), rf.beforeMsg)
				}
				// Stateless temp DB holds only this run → whole-DB report ("").
				if err := generateReportFromDB(ctx, db, outPath, opts.OmitResponse, "", rf.generate); err != nil {
					fmt.Fprintf(os.Stderr, "%s Failed to generate %s: %v\n", terminal.ErrorPrefix(), rf.label, err)
				} else {
					fmt.Fprintf(os.Stderr, "%s %s exported to %s\n", terminal.InfoSymbol(), rf.label, terminal.Cyan(outPath))
				}
			}
		}
	}
}

// exportProjectScope returns the project filter for a post-scan export: empty
// (whole DB) for stateless runs, whose temp DB holds only this scan; the run's
// project (defaulting to DefaultProjectUUID) for persisted runs, so the export
// is scoped to this scan's project on a shared DB. Shared by the jsonl and
// report post-scan exporters so their scopes stay in sync.
func exportProjectScope(opts *types.Options) string {
	if opts.Stateless {
		return ""
	}
	if opts.ProjectUUID != "" {
		return opts.ProjectUUID
	}
	return database.DefaultProjectUUID
}

// encodeJSONL writes each item to w as a unified {"type":...,"data":...} envelope
// line, returning the number written. Callers query first (so a query failure
// never leaves a created-but-empty output file) and encode into an already-open
// writer here.
func encodeJSONL(w io.Writer, items []any) (int, error) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

// writeJSONLExport queries the (optionally project-scoped) database and streams
// the envelope to w. projectUUID == "" exports the whole DB. Used for the stdout
// path, where there is no output file to leave half-written on error.
func writeJSONLExport(ctx context.Context, db *database.DB, w io.Writer, omitResponse bool, projectUUID string) (int, error) {
	items, err := queryExportData(ctx, db, omitResponse, projectUUID)
	if err != nil {
		return 0, err
	}
	return encodeJSONL(w, items)
}

// exportStatelessJSONL writes all records in the (temporary) database to a JSONL
// file. Used only in stateless mode, where the temp DB holds just this run, so
// the whole-DB export is implicitly scoped to the current scan. The query runs
// before the file is created so a query failure leaves no empty output file.
func exportStatelessJSONL(ctx context.Context, db *database.DB, opts *types.Options, outputPath string) {
	items, err := queryExportData(ctx, db, opts.OmitResponse, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to export data: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output file: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	defer func() { _ = f.Close() }()

	n, err := encodeJSONL(f, items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to write export data: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s Results exported to %s (%d records)\n",
		terminal.InfoSymbol(), terminal.Cyan(outputPath), n)
}

// finishScanJSONLExport emits the post-scan unified JSONL envelope for a scan
// run with --format jsonl. Persisted runs are scoped to the scan's project;
// stateless runs export the whole temp DB. Output goes to the -o file or, when
// no -o was given, to stdout. Stateless runs WITH -o are materialized by
// finishStatelessExport (all formats), so only the stateless no-output case is
// handled here (otherwise jsonl results would be silently discarded with the
// temp DB). CI output keeps its own emitter and never sets DeferredJSONLExport.
func finishScanJSONLExport(db *database.DB, opts *types.Options) {
	if !opts.DeferredJSONLExport {
		return
	}
	if opts.Stateless && opts.Output != "" {
		return
	}
	ctx := context.Background()
	projectUUID := exportProjectScope(opts)

	if opts.Output == "" {
		// No -o: stream the envelope to stdout once the scan completes.
		if _, err := writeJSONLExport(ctx, db, os.Stdout, opts.OmitResponse, projectUUID); err != nil {
			fmt.Fprintf(os.Stderr, "%s Failed to export results: %v\n", terminal.ErrorPrefix(), err)
		}
		return
	}

	items, err := queryExportData(ctx, db, opts.OmitResponse, projectUUID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to export results: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	// Single format honors the literal -o path the user gave; with multiple
	// formats each writes to its own extension-qualified path so the jsonl
	// export never collides with the live console / html / report files.
	outPath := opts.Output
	if len(opts.OutputFormats) > 1 {
		outPath = opts.OutputPathForFormat("jsonl")
	}
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output file: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	defer func() { _ = f.Close() }()

	n, err := encodeJSONL(f, items)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to export results: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s Results exported to %s (%d records)\n",
		terminal.InfoSymbol(), terminal.Cyan(outPath), n)
}

// exportStatelessConsole writes all database records to a plain-text file using
// the same human-readable layout as the live console output (minus ANSI colors
// and the phase prefix, which don't belong in a file). Used for stateless runs
// with the default console format so -o always produces a populated file even
// when the phase only ingests HTTP records (e.g. discovery) and emits no
// findings.
func exportStatelessConsole(ctx context.Context, db *database.DB, outputPath string, omitResponse bool) {
	items, err := queryExportData(ctx, db, omitResponse, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to export data: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to create output file: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(f)
	var lines int
	for _, item := range items {
		env, ok := item.(exportEnvelope)
		if !ok {
			continue
		}
		var line string
		switch env.Type {
		case "http_record":
			line = consoleHTTPRecordLine(env.Data)
		case "finding":
			line = consoleFindingLine(env.Data)
		}
		if line == "" {
			continue
		}
		_, _ = fmt.Fprintln(w, line)
		lines++
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "%s Failed to write export data: %v\n", terminal.ErrorPrefix(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s Results exported to %s (%d lines)\n",
		terminal.InfoSymbol(), terminal.Cyan(outputPath), lines)
}

// consoleHTTPRecordLine renders an HTTP record export item as a plain-text
// console-style line: [status] METHOD content-type url
func consoleHTTPRecordLine(data any) string {
	r, ok := data.(*database.HTTPRecord)
	if !ok {
		return ""
	}
	return fmt.Sprintf("[%d] %s %s %s", r.StatusCode, r.Method, shortContentType(r.ResponseContentType), r.URL)
}

// consoleFindingLine renders a finding export item as a plain-text
// console-style line: [severity] [module-id] location [extracted-results]
func consoleFindingLine(data any) string {
	f, ok := data.(*database.Finding)
	if !ok {
		return ""
	}
	loc := f.URL
	if len(f.MatchedAt) > 0 && f.MatchedAt[0] != "" {
		loc = f.MatchedAt[0]
	}
	if loc == "" {
		loc = f.Hostname
	}
	line := fmt.Sprintf("[%s] [%s] %s", strings.ToUpper(f.Severity), f.ModuleID, loc)
	if len(f.ExtractedResults) > 0 {
		line += " [" + strings.Join(f.ExtractedResults, ",") + "]"
	}
	return line
}

// shortContentType trims parameters from a content type
// (application/json; charset=utf-8 → application/json), returning "-" when empty.
func shortContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if ct = strings.TrimSpace(ct); ct == "" {
		return "-"
	}
	return ct
}

func setupScanSignalHandler(r *runner.Runner) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		// First Ctrl+C: graceful shutdown
		<-c
		zap.L().Info("CTRL+C pressed: Exiting")
		zap.L().Info("Attempting graceful shutdown...")

		// Start graceful Close in a goroutine
		closeDone := make(chan struct{})
		go func() {
			r.Close()
			close(closeDone)
		}()

		// Wait for Close to finish or a second Ctrl+C
		select {
		case <-closeDone:
			// Graceful shutdown completed
		case <-c:
			zap.L().Warn("Second CTRL+C received, forcing exit")
			os.Exit(1)
		}
	}()
}

// printScanSummary prints a human-readable scan configuration overview to stderr.
func printScanSummary(opts *types.Options, settings *config.Settings, strategyName string, repo *database.Repository) {
	if opts.Silent || globalJSON || globalCIOutput {
		return
	}

	// Credit the discovery co-authors when the run is discovery/spidering-only
	// (e.g. `vigolium run discover` or `vigolium scan --only discovery`).
	if isDiscoveryOnlyPhases(opts.OnlyPhase) {
		fmt.Fprint(os.Stderr, GetDiscoveryBanner())
	} else {
		fmt.Fprint(os.Stderr, GetBanner())
	}

	// Phase status indicators: symbol + colored name + optional pace detail
	phaseLabel := func(name, phasePaceKey string, enabled bool) string {
		label := name
		if !enabled {
			return terminal.Gray(terminal.SymbolError) + " " + terminal.Gray(label)
		}
		// Append max_duration / duration_factor if set
		resolved := settings.ScanningPace.ResolvePhase(phasePaceKey)
		var paceDetail string
		if resolved.MaxDuration > 0 {
			paceDetail = resolved.MaxDuration.String()
		}
		if resolved.DurationFactor > 0 {
			if paceDetail != "" {
				paceDetail += fmt.Sprintf(", x%.1f", resolved.DurationFactor)
			} else {
				paceDetail = fmt.Sprintf("x%.1f", resolved.DurationFactor)
			}
		}
		if paceDetail != "" {
			label += " " + terminal.Gray("("+paceDetail+")")
		}
		return terminal.Green(terminal.SymbolSuccess) + " " + terminal.HiCyan(label)
	}

	discoveryEnabled := opts.DiscoverEnabled
	spideringEnabled := opts.SpideringEnabled
	knownIssueScanEnabled := opts.KnownIssueScanEnabled
	daEnabled := !opts.SkipDynamicAssessment
	ehEnabled := opts.ExternalHarvestEnabled

	// Strategy name
	strategy := strategyName
	if strategy == "" {
		strategy = "default"
	}

	// Module counts
	var activeCount, passiveCount int
	if len(opts.Modules) > 0 && opts.Modules[0] == "all" {
		activeCount = len(modules.GetActiveModules())
	} else {
		activeCount = len(modules.GetActiveModulesByIDs(opts.Modules))
	}
	passiveCount = len(modules.GetPassiveModules())

	// Scope origin mode
	scopeOrigin := settings.Scope.CLIOriginMode
	if scopeOrigin == "" {
		scopeOrigin = "relaxed"
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("run"), terminal.HiCyan("vigolium traffic list"), terminal.Gray("and"), terminal.HiCyan("vigolium findings list"), terminal.Gray("to view ingested data and vulnerabilities"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
		terminal.TipPrefix(), terminal.Gray("run each phase separately via"), terminal.HiCyan("vigolium run <phase>"), terminal.Gray("(e.g. vigolium run dynamic-assessment)"))
	fmt.Fprintf(os.Stderr, "  %s %s %s %s\n\n",
		terminal.TipPrefix(), terminal.Gray("skip phases you don't need via"), terminal.HiCyan("--skip <phase>"), terminal.Gray("(e.g. --skip discovery,known-issue-scan)"))
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.Green(terminal.SymbolStart), terminal.BoldHiBlue("Native Scan Configuration"))
	if opts.ScanUUID != "" {
		fmt.Fprintf(os.Stderr, "  %s Scan ID: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanUUID))
	}
	if opts.Stateless {
		statelessLine := "Stateless mode: using temporary database"
		if globalVerbose && settings.Database.SQLite.Path != "" {
			statelessLine += " " + terminal.Gray("("+settings.Database.SQLite.Path+")")
		}
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), statelessLine)
	}
	if opts.ProjectUUID != "" {
		fmt.Fprintf(os.Stderr, "  %s Project: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ProjectUUID))
	}
	fmt.Fprintf(os.Stderr, "  %s Strategy: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(strategy))
	if opts.ScanningProfile != "" {
		fmt.Fprintf(os.Stderr, "  %s Profile: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(opts.ScanningProfile))
	}
	targetsLine := fmt.Sprintf("Targets: %s (CLI: %s)", terminal.Orange(fmt.Sprintf("%d", len(opts.Targets))), terminal.HiBlue(strings.Join(opts.Targets, ", ")))
	if opts.TargetsFilePath != "" {
		targetsLine += fmt.Sprintf(" (+ file: %s)", terminal.HiTeal(opts.TargetsFilePath))
	}
	if repo != nil {
		ctx := context.Background()
		if dbCount, err := repo.CountRecordsAfterCursor(ctx, time.Time{}, ""); err == nil && dbCount > 0 {
			targetsLine += fmt.Sprintf(" | %s (HTTP Records)", terminal.Orange(fmt.Sprintf("%d", dbCount)))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolTarget), targetsLine)
	fmt.Fprintf(os.Stderr, "  %s Phases: %s | %s | %s\n",
		terminal.Purple(terminal.SymbolInfo),
		phaseLabel("ExternalHarvest", "external_harvester", ehEnabled),
		phaseLabel("Spidering", "spidering", spideringEnabled),
		phaseLabel("Discovery", "discovery", discoveryEnabled))
	fmt.Fprintf(os.Stderr, "           %s | %s\n",
		phaseLabel("KnownIssueScan", "known-issue-scan", knownIssueScanEnabled),
		phaseLabel("DynamicAssessment", "dynamic-assessment", daEnabled))
	heuristicsDesc := map[string]string{
		"basic":    "probe target root pages to detect content type (HTML, JSON, blank) and skip spidering for non-HTML targets",
		"advanced": "basic checks + deep HTML analysis to detect SPA frameworks and optimize phase selection",
		"none":     "skip all heuristic probes, run all enabled phases unconditionally",
	}
	if desc, ok := heuristicsDesc[opts.HeuristicsCheck]; ok {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck),
			terminal.Gray(desc))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Heuristics: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(opts.HeuristicsCheck))
	}
	fmt.Fprintf(os.Stderr, "  %s Speed: concurrency=%s | rate-limit=%s | max-per-host=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", opts.Concurrency)),
		terminal.HiBlue(fmt.Sprintf("%d", globalRateLimit)),
		terminal.HiBlue(fmt.Sprintf("%d", opts.MaxPerHost)))
	originDesc := map[string]string{
		"relaxed":  "host must contain the target's keyword (e.g. \"example\")",
		"all":      "no origin restriction, all hosts are in scope",
		"balanced": "host must share the target's eTLD+1 (e.g. *.example.com)",
		"strict":   "host must exactly match the target host",
	}
	originDescStr := ""
	if desc, ok := originDesc[scopeOrigin]; ok {
		originDescStr = " " + terminal.Gray(desc)
	}
	fmt.Fprintf(os.Stderr, "  %s Scope: origin=%s | ignore-static=%s%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiPurple(scopeOrigin),
		terminal.HiPurple(fmt.Sprintf("%v", settings.Scope.IgnoreStaticFile)),
		originDescStr)
	modulesLine := fmt.Sprintf("Modules: %s active, %s passive",
		terminal.Orange(fmt.Sprintf("%d", activeCount)),
		terminal.Orange(fmt.Sprintf("%d", passiveCount)))
	if settings != nil && settings.DynamicAssessment.Extensions.Enabled {
		extCount := countExtensionFiles(&settings.DynamicAssessment.Extensions)
		modulesLine += fmt.Sprintf(" + %s extensions", terminal.HiTeal(fmt.Sprintf("%d", extCount)))
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Purple(terminal.SymbolInfo), modulesLine)
	// Output destination & format(s) — shown when -o or a non-default --format
	// is in play so it's clear where (and in what shape) results land.
	formats := opts.OutputFormats
	if len(formats) == 0 {
		formats = []string{"console"}
	}
	isDefaultFormat := len(formats) == 1 && formats[0] == "console"
	if opts.Output != "" || !isDefaultFormat {
		formatStr := strings.Join(formats, ", ")
		dest := "stdout"
		if opts.Output != "" {
			base := types.StripFormatExtension(opts.Output)
			seen := make(map[string]struct{}, len(formats))
			paths := make([]string, 0, len(formats))
			for _, f := range formats {
				p := types.FormatOutputPath(base, f)
				if p == "" {
					continue
				}
				if _, dup := seen[p]; dup {
					continue
				}
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
			if len(paths) > 0 {
				dest = strings.Join(paths, ", ")
			}
		}
		fmt.Fprintf(os.Stderr, "  %s Output: %s %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(dest),
			terminal.Gray("(format: "+formatStr+")"))
	}
	if globalVerbose {
		fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("view scope details via"), terminal.HiCyan("vigolium config ls scope"))
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.TipPrefix(), terminal.Gray("view scanning pace via"), terminal.HiCyan("vigolium config ls scanning_pace"))
		if knownIssueScanEnabled && !settings.KnownIssueScan.EnrichTargets {
			fmt.Fprintf(os.Stderr, "  %s %s %s\n",
				terminal.TipPrefix(), terminal.Gray("enrich KnownIssueScan targets with discovered paths via"), terminal.HiCyan("vigolium config known_issue_scan.enrich_targets=true"))
		}
	}
	fmt.Fprintln(os.Stderr)
}

// countExtensionFiles counts JS/TS/YAML extension files from the configured directories without loading them.
func countExtensionFiles(cfg *config.ExtensionsConfig) int {
	count := len(cfg.CustomDir)

	if cfg.ExtensionDir != "" {
		dir := config.ExpandPath(cfg.ExtensionDir)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				if strings.HasSuffix(name, ".d.ts") {
					continue
				}
				if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts") || strings.HasSuffix(name, ".vgm.yaml") {
					count++
				}
			}
		}
	}

	return count
}

// printScanCompletionSummary prints a compact summary of ingested records,
// findings, and total wall-clock duration after scan completion.
func printScanCompletionSummary(repo *database.Repository, elapsed time.Duration) {
	if repo == nil {
		return
	}

	ctx := context.Background()
	db := repo.DB()

	// Count HTTP records
	var recordCount int
	err := db.NewSelect().Model((*database.HTTPRecord)(nil)).ColumnExpr("COUNT(*)").Scan(ctx, &recordCount)
	if err != nil {
		return
	}

	// Count findings by severity
	type sevCount struct {
		Severity string `bun:"severity"`
		Count    int64  `bun:"count"`
	}
	var sevCounts []sevCount
	err = db.NewSelect().Model((*database.Finding)(nil)).
		ColumnExpr("severity, COUNT(*) AS count").
		GroupExpr("severity").
		Scan(ctx, &sevCounts)
	if err != nil {
		return
	}

	var totalFindings int64
	counts := make(map[string]int64)
	for _, sc := range sevCounts {
		counts[sc.Severity] = sc.Count
		totalFindings += sc.Count
	}

	fmt.Fprintf(os.Stderr, "  %s Records: %s http records ingested\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Cyan(fmt.Sprintf("%d", recordCount)))

	// Total scan duration always prints last, after Records and the Findings line
	// (whichever branch runs below). Registered here — not at function entry — so
	// the rare DB-error early returns above don't emit a lone Duration line.
	defer func() {
		fmt.Fprintf(os.Stderr, "  %s Duration: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray(elapsed.Round(time.Second).String()))
	}()

	if totalFindings == 0 {
		fmt.Fprintf(os.Stderr, "  %s Findings: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.Gray("no issues found"))
		return
	}

	// Build severity breakdown
	var parts []string
	for _, s := range []struct {
		key string
		fn  func(string) string
		sym func() string
	}{
		{"critical", terminal.BoldMagenta, terminal.CriticalSymbol},
		{"high", terminal.BoldRed, terminal.HighSymbol},
		{"medium", terminal.BoldYellow, terminal.MediumSymbol},
		{"low", terminal.BoldGreen, terminal.LowSymbol},
		{"suspect", terminal.BoldCyan, terminal.SuspectSymbol},
		{"info", terminal.BoldBlue, terminal.InfoSeveritySymbol},
	} {
		if c, ok := counts[s.key]; ok && c > 0 {
			parts = append(parts, fmt.Sprintf("%s %s %s", s.sym(), s.fn(fmt.Sprintf("%d", c)), s.key))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Findings: %s issues found — %s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.Orange(fmt.Sprintf("%d", totalFindings)),
		strings.Join(parts, ", "))
}
