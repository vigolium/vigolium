package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

var scanOpts = types.DefaultOptions()

// scanReportSharedURL holds the --report-url flag value for native-scan HTML report rendering.
var scanReportSharedURL string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a native scan — deterministic multi-phase vulnerability scanning",
	Long: `Run the native scan pipeline against one or more targets. Phases run in order:
ingestion → discovery → external-harvest → spidering → known-issue-scan → dynamic-assessment → extension.

Use --only / --skip to limit phases, --strategy or --scanning-profile for tuned presets, and --ext / --ext-dir to load custom JavaScript extensions.

Targets may be passed as positional URLs (vigolium scan https://a https://b), via
repeated -t/--target, or from -T/--target-file; the three combine and duplicates
are removed. A positional value is always treated as a target URL, never a file —
use -T or -i for files. A UUID-shaped positional is rejected as a mistyped
subcommand (see 'vigolium scan diff').`,
	Args: cobra.ArbitraryArgs,
	RunE: runScanCmd,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	flags := scanCmd.Flags()
	registerInputSourceFlags(flags)
	registerAllRecordsFlag(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerModuleSelectionFlags(flags)
	registerScanPipelineFlags(flags)
	registerSpecFlags(flags)
	flags.StringVar(&scanOpts.FingerprintDepth, "fingerprint-depth", "", "With the fingerprint phase: reads per origin, light|standard|full (default standard, light past 50 targets; 'vigolium fingerprint --depth')")
	registerNativeScanFlags(flags, true)
	addFlagAliases(scanCmd, nativeScanFlagAliases)
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

// mergePositionalTargets combines positional target URLs with repeated --target
// values, preserving order (positional first) and removing duplicates and blanks.
// It normalizes the scheme here as well as in runner.NewWithInputSource, where
// every entry point is caught: doing it before the dedup is what collapses
// `example.com` and `http://example.com` into one target rather than two, and it
// is the spelling the banner goes on to print.
// The second return names the targets whose scheme this merge SUPPLIED, for
// Options.TargetsSchemeAssumed. Normalization is what destroys the distinction
// between "the operator typed http" and "we guessed http", and the probe sweep
// needs it to know which guesses it may test — so the merge that destroys it
// is the only place that can report it.
func mergePositionalTargets(positional, flagged []string) (targets []string, assumed map[string]struct{}) {
	seen := make(map[string]bool, len(positional)+len(flagged))
	out := make([]string, 0, len(positional)+len(flagged))
	for _, src := range [][]string{positional, flagged} {
		for _, t := range src {
			t, guessed := httpmsg.EnsureURLSchemeTracked(strings.TrimSpace(t), httpmsg.DefaultTargetScheme)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
			if guessed {
				if assumed == nil {
					assumed = make(map[string]struct{})
				}
				assumed[t] = struct{}{}
			}
		}
	}
	return out, assumed
}

func runScanCmd(cmd *cobra.Command, args []string) (err error) {
	defer syncLogger()

	// --fail-on gate: validate up front, then convert a tripped gate into a
	// non-zero exit once the body has returned (so reports/JSON are written
	// first). evaluateFailOnGate sets the flag during reportNativeScanSuccess.
	// Under -P/--parallel the gate is a no-op here — each child process runs its
	// own runScanCmd and exits non-zero on its own findings.
	if gateErr := resetFailOnGate(); gateErr != nil {
		return gateErr
	}
	defer func() { err = withFailOnGate(err) }()

	// A UUID where a target goes is a mistyped subcommand (`scan staus <uuid>`),
	// not a host; see rejectUUIDScanTargets.
	if err := rejectUUIDScanTargets(cmd, args); err != nil {
		return err
	}

	// Copy global flags into scan options
	scanOpts.ScanUUID = globalScanUUID
	if err := validateModuleSelectionFlags(false); err != nil {
		return err
	}
	applyModuleSelection(scanOpts, false)
	// Positional URLs combine with repeated -t/--target (positional first),
	// de-duplicated. `run` passes nil here since its positional arg is a phase.
	var schemeAssumed map[string]struct{}
	scanOpts.Targets, schemeAssumed = mergePositionalTargets(args, globalTargets)
	scanOpts.MarkSchemeAssumed(schemeAssumed)
	scanOpts.TargetsFilePaths = globalTargetFiles
	scanOpts.InputFileMode = globalInputMode
	scanOpts.InputFileModeExplicit = cmd.Flags().Changed("input-mode")
	globalScanFlagsToOptions(scanOpts)
	// globalChanged, not cmd.Flags().Changed: pflag marks a flag Changed when only
	// its PHASE-QUALIFIED form was typed, so `--concurrency known-issue-scan=5`
	// would read as an explicit global concurrency — which makes the runner refuse
	// to read the very per-phase value that flag just wrote.
	scanOpts.ConcurrencyExplicitlySet = concurrencyKnob.globalChanged()
	scanOpts.MaxPerHostExplicitlySet = maxPerHostKnob.globalChanged()
	// --rate-limit applies whether or not it was typed. It used to be copied only
	// under cmd.Flags().Changed, which left an unset flag meaning "no cap at all"
	// while its own help text advertised a default of 100 — silence resolving to
	// unlimited, i.e. the fail-OPEN direction on a safety knob, and a documented
	// default the code never applied. The no-cap case now requires asking for it
	// (--rate-limit 0); negative values are rejected by the flag parser.
	scanOpts.RateLimit = globalRateLimit
	// Targets and TargetsFilePaths are bound above, so both are readable here.
	scanOpts.Stdin, scanStdinExplicit = resolveStdinInput(
		fileutil.HasStdin(),
		cmd.Flags().Changed("input"), globalInput,
		len(scanOpts.Targets), len(scanOpts.TargetsFilePaths),
	)
	// --all-records names the input source outright, the way -t does, so an
	// inherited pipe is not it. A typed -i - is still seen, and rejected as a
	// conflict by resolveScanTargetSource.
	if globalAllRecords && !scanStdinExplicit {
		scanOpts.Stdin = false
	}
	scanOpts.OnlyPhase = globalOnly
	scanOpts.SkipPhases = globalSkipPhases
	scanOpts.ScopeOriginMode = globalScopeOrigin
	scanOpts.OutputFormats = parseFormats(globalFormat)
	// Validated here, before any network or database work: a typo in --events
	// should fail in milliseconds, not after a 15-minute crawl whose whole reason
	// for running was the stream it never produced.
	if err := validateEventsFlag(scanOpts.Events); err != nil {
		return asUsageError(err)
	}
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	scanOpts.ProjectUUID = projectUUID

	if err := reconcileOutputFormats(scanOpts); err != nil {
		return err
	}
	// After reconcileOutputFormats, which sets CIOutput from the flag: -j's scan
	// document and --events each own stdout, and any second writer there is a
	// usage error.
	if err := validateStdoutProtocol(scanOpts); err != nil {
		return err
	}
	if err := validateScanDocumentFlags(); err != nil {
		return err
	}
	noteCIOutputDeprecated()

	// Stateless mode validation. The db-isolate precedence runs BEFORE the flag
	// is copied into Options, so the copy below is already the resolved value and
	// there is never a second place to clear.
	scanOpts.Stateless = globalStateless
	scanOpts.SplitByHost = globalSplitByHost
	dbIsolateYieldsToStateless(scanOpts.Stateless)
	scanOpts.DBIsolate = globalDBIsolate
	scanOpts.Parallel = globalParallel
	scanOpts.Resume = globalResume

	// Bare `vigolium scan --resume` (no -T/-t/stdin to scan): auto-discover the
	// progress manifest in the working directory and relaunch the saved run from
	// it, so the operator can resume a fan-out without re-typing every flag. With
	// targets present this is skipped and --resume continues through the normal
	// path (which narrows the fan-out to the unscanned tail).
	if scanOpts.Resume && len(scanOpts.TargetsFilePaths) == 0 && len(scanOpts.Targets) == 0 && !scanOpts.Stdin {
		return resumeFromDiscoveredManifest(cmd)
	}

	// --split-by-host names each per-host output file after the target's hostname
	// (acme-<host>.jsonl with a base, or just <host>.jsonl when no -o is given), so
	// the host already disambiguates files and -o/--output is OPTIONAL in that mode.
	// Only true when the flag will actually take effect (the dispatch only takes the
	// split path for a stateless multi-target file scan), so file-based formats still
	// require -o everywhere else.
	splitByHostNaming := scanOpts.SplitByHost && scanOpts.Stateless && len(scanOpts.TargetsFilePaths) > 0

	// Supplying a fuzz wordlist and disabling fuzzing states two opposite
	// intents. Resolving it silently either way leaves the operator believing
	// the other one took effect, and the two outcomes differ by thousands of
	// requests per host — so it is an error rather than a precedence rule.
	if scanOpts.NoDiscoveryFuzz && len(scanOpts.FuzzWordlistPaths) > 0 {
		return usageErrorf("--no-discovery-fuzz and --discovery-wordlist are mutually exclusive (--discovery-wordlist exists to turn discovery fuzzing on; drop one)")
	}
	wordlistPaths, werr := normalizeDiscoveryWordlists(scanOpts.FuzzWordlistPaths)
	if werr != nil {
		return werr
	}
	scanOpts.FuzzWordlistPaths = wordlistPaths
	if err := validateParallelScan(scanOpts); err != nil {
		return err
	}
	if err := validateKeepDBOnError(scanOpts.Stateless); err != nil {
		return err
	}
	if scanOpts.Stateless {
		if globalDB != "" {
			return usageErrorf("--stateless and --db are mutually exclusive")
		}
		// Not warned under --json/--ci-output: the scan document (findings up
		// to --limit, with the counts) and the CI finding lines carry the
		// results to stdout before the temporary database goes away. Telling
		// an operator reading them that their output is being thrown away is
		// worse than saying nothing.
		if scanOpts.Output == "" && !scanOpts.Silent && !splitByHostNaming && !globalJSON && !globalCIOutput {
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

	// Load settings from config file. A failure here is fatal: only an EXPLICIT
	// --config reaches this branch (clicommon.LoadSettings degrades a discovered
	// one to defaults with a warning), and running a scan under settings the
	// operator did not choose — a different database, a different scope, a
	// different rate limit — is worse than not running it. The old branch printed
	// "Config file not found, using defaults", which was wrong twice: the file is
	// usually found and unparseable, and "using defaults" was the problem.
	//
	// The project layer comes with it: global → the resolved project's overlay
	// (`scope set --project`, `project config`), then the profile and CLI layers
	// in resolveNativeScanOptions below.
	settings, err := loadProjectSettings(scanOpts.ConfigPath)
	if err != nil {
		return err
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

	// A negative budget is an already-expired deadline, not "unlimited": every
	// consumer feeds it straight to context.WithTimeout, so the phase it governs
	// does nothing and reports no error. Reject it before any side effect rather
	// than silently running an empty scan. (Zero stays legal and means "default"
	// for these two phases — see docs/configuration.md.)
	for _, d := range []struct {
		flag  string
		value time.Duration
	}{
		{"discover-max-time", scanOpts.DiscoverMaxDuration},
		{"spider-max-time", scanOpts.SpideringMaxDuration},
		{"max-time", globalScanningMaxDuration},
	} {
		if d.value < 0 {
			return fmt.Errorf("--%s must not be negative, got %s", d.flag, d.value)
		}
	}

	// Scan-options resolution: profile → settings overrides (--oast-url,
	// --scope-origin, --scanning-max-duration) → strategy (explicit rate limit,
	// phases, pace ceiling, heuristics) → --only/--skip → per-phase qualifiers →
	// scanning_pace. REST and the agent launcher run the same runner functions;
	// the ordering contract lives in runner/strategy_apply.go.
	strategyName, err := resolveNativeScanOptions(cmd, settings, scanOpts)
	if err != nil {
		return err
	}

	// HTML's -o requirement is covered by the generic formatNeedsOutput loop
	// below; only the phase restriction is html-specific.
	if scanOpts.HasFormat("html") {
		if phases := runner.OnlyPhaseSet(scanOpts.OnlyPhase); len(phases) > 0 {
			for p := range phases {
				if p != "discovery" && p != "spidering" {
					return usageErrorf("--format html is only supported for discovery and spidering phases")
				}
			}
		}
	}

	for _, f := range scanOpts.OutputFormats {
		if formatNeedsOutput(f) && scanOpts.Output == "" && !splitByHostNaming {
			return usageErrorf("--format %s requires -o/--output to specify the output file path (or pass --split-by-host to name per-host files by hostname)", f)
		}
	}

	// Multi-format requires -o/--output for file-based formats — unless
	// --split-by-host supplies a per-host base from each target's hostname.
	if len(scanOpts.OutputFormats) > 1 && scanOpts.Output == "" && !splitByHostNaming {
		return fmt.Errorf("multiple --format values require -o/--output to specify the base output path (or pass --split-by-host to name per-host files by hostname)")
	}

	// --discovery-extensions / --discovery-max-depth override the discovery
	// config before it is validated.
	if err := applyDiscoveryFlagOverrides(cmd, &settings.Discovery, scanOpts); err != nil {
		return err
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
		applyKnownIssueScanTemplateFlags(cmd, &settings.KnownIssueScan, scanOpts)
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
		if cmd.Flags().Changed("browser-insecure") {
			settings.Spidering.BrowserCompat.SetAll(scanOpts.SpideringBrowserInsecure)
		}
		if cmd.Flags().Changed("require-auth") {
			settings.Spidering.RequireAuth = scanOpts.SpideringRequireAuth
		}
		if err := settings.Spidering.Validate(); err != nil {
			return fmt.Errorf("invalid spidering configuration: %w", err)
		}
	}
	if scanNoCarryBrowserSession {
		scanOpts.CarryBrowserSession = false
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

	// No implicit work: no target source without --all-records is a usage error
	// (a deprecation warning on a TTY), and --all-records must stand alone. Then
	// drain a piped URL list now, so an inherited pipe that never writes fails in
	// seconds instead of after the database, banner and scan.started.
	if err := resolveScanTargetSource(cmd, settings); err != nil {
		return err
	}
	if err := prefetchScanStdin(); err != nil {
		return err
	}

	// A target file that yields no targets is a misconfiguration in every mode;
	// fail loudly rather than running a zero-target scan that reports "completed".
	// (The --split-by-host path re-checks this in runStatelessTargetFile; the
	// shared fall-through below otherwise has no such guard.)
	if len(scanOpts.TargetsFilePaths) > 0 {
		fileTargets, terr := readTargetFilesLines(scanOpts.TargetsFilePaths)
		if terr != nil {
			return terr
		}
		if len(fileTargets) == 0 {
			return fmt.Errorf("target file(s) %s contain no targets", strings.Join(scanOpts.TargetsFilePaths, ", "))
		}
	}

	// -i with no -t: scope to the input's primary host instead of every host
	// the file names (SAFE-4). Before --dry-run so the plan shows it.
	deriveFileInputScope(settings, scanOpts)

	// --dry-run: resolve and print the plan, then stop — before any fan-out,
	// scan uuid, scan row, output file, wordlist, login or OAST registration.
	if scanDryRun {
		return runScanDryRun(cmd, settings, strategyName)
	}

	// DB-isolate parallel fan-out (-P > 1 with --db-isolate): scan each target as
	// an isolated child that merges into --db, then export one unified output from
	// the merged DB. -P 1 / a single target falls through to the single-process
	// path below, which already scans the whole file into one scratch and merges.
	if scanOpts.DBIsolate && scanOpts.Parallel > 1 && len(scanOpts.TargetsFilePaths) > 0 {
		return runIsolatedTargetsParallel(cmd, settings, strategyName)
	}

	// Multi-target stateless with --split-by-host: iterate per line with a fresh
	// temp DB each time, writing one per-host output file per target. Without the
	// flag, fall through to a single shared pass so the whole target file scans
	// into one temp DB and exports to one unified output file (all formats).
	if scanOpts.Stateless && len(scanOpts.TargetsFilePaths) > 0 && scanOpts.SplitByHost {
		return runStatelessTargetFile(cmd, settings, strategyName)
	}

	return executeNativeScan(cmd, settings, strategyName)
}
