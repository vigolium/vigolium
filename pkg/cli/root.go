package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/memlimit"
	"github.com/vigolium/vigolium/internal/paths"
	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// Global flags shared across all commands
var (
	globalVerbose                 bool
	globalSilent                  bool
	globalDebug                   bool
	globalDumpTraffic             bool
	globalLogFile                 string
	globalJSON                    bool
	globalConfig                  string
	globalProxy                   string
	globalDB                      string
	globalTargets                 []string
	globalTargetFiles             []string
	globalInputMode               string
	globalTimeout                 time.Duration
	globalConcurrency             int
	globalScanOnReceive           bool
	globalFullNativeScanOnReceive bool
	globalMaxPerHost              int
	globalNoWafPacing             bool
	globalMaxHostError            int
	globalMaxFindingsPerModule    int
	globalListModules             bool
	globalListInputModes          bool
	globalForce                   bool
	globalDisableFetchResponse    bool
	globalWidth                   int
	globalSkipDependencyCheck     bool
	globalSoftFail                bool

	// Input / server / module flags (shared by scan, ingest, etc.)
	globalInput       string
	globalRateLimit   int
	globalModules     []string
	globalModuleTags  []string
	globalModuleIDs   []string
	globalPassiveOnly bool
	globalScanUUID    string
	globalSpecURL     bool
	globalSpecHeader  []string
	globalSpecVar     []string
	globalSpecDefault string

	// Phase isolation
	globalOnly       string
	globalSkipPhases []string

	// Scanning strategy preset
	globalStrategy string

	// Heuristics check
	globalHeuristicsCheck string
	globalSkipHeuristics  bool

	// Scanning profile (name or path)
	globalScanningProfile string

	// Scan intensity preset (quick, balanced, deep)
	globalIntensity string

	// Disable the tech-stack allowlist gate (also auto-disabled by --intensity=deep)
	globalNoTechFilter bool

	// Watch mode: re-run queries at interval
	globalWatchRaw string

	// Scope origin mode
	globalScopeOrigin string
	globalOffline     bool

	// Scanning pace override
	globalScanningMaxDuration time.Duration

	// Output format
	globalFormat   string
	globalCIOutput bool
	globalNoColor  bool

	// Full example flag
	globalFullExample bool

	// On-demand extension loading
	globalExtScripts       []string // --ext
	globalExtDir           string   // --ext-dir
	globalExtAllowFailures bool     // --ext-allow-failures

	// Stateless mode
	globalStateless   bool
	globalSplitByHost bool
	globalDBIsolate   bool
	globalParallel    int
	globalResume      bool

	// Memory ceiling (GOMEMLIMIT)
	globalMemLimit string

	// globalInputReadTimeout backs --input-read-timeout. It carries the default
	// in its initializer rather than relying on pflag, because zero is now a
	// meaningful value ("no deadline") and the commands that never register the
	// flag must still be bounded. See stdinReadTimeout in stdin.go.
	globalInputReadTimeout = defaultInputReadTimeout

	// scanHeapCeiling is the heap-ceiling outcome derived by applyScanMemLimit.
	// The scan banner renders it (colored) after the logo, but only for a
	// parallel fan-out (-P > 1) — see printScanSummary.
	scanHeapCeiling memlimit.Result

	// Request clustering
	globalNoClustering bool

	// Multi-tenancy
	globalProjectUUID string
	globalProjectName string

	// projectFromEnv records that the project selection above came from
	// VIGOLIUM_PROJECT_UUID / VIGOLIUM_PROJECT_NAME rather than from a flag. The
	// two are identical once folded in, and that is the point — but a filter the
	// operator cannot see in the command they just typed is worth one line of
	// notice when it narrows a standalone read. See noteEnvProjectFilter.
	projectFromEnv bool
)

var rootCmd = &cobra.Command{
	Use:   "vigolium",
	Short: "Vigolium - High-fidelity vulnerability scanner with native scan precision and agentic scan intelligence",
	Long: `Vigolium is a web vulnerability scanner that combines a deterministic native engine with AI-driven (agentic) scanning.

Common workflows:
  • vigolium scan        — run the full native pipeline against a target
  • vigolium agent       — run an agentic scan (autopilot, swarm, query, olium)
  • vigolium server      — start the REST API + ingest proxy
  • vigolium ingest      — push HTTP traffic into the database
  • vigolium finding     — inspect and export scan findings
  • vigolium traffic     — inspect and export captured HTTP traffic

Run 'vigolium <command> --help' for command-specific flags and examples, or 'vigolium --full-example' for a curated tour.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logger for all commands
		zapLogger := initLogger(globalVerbose, globalSilent, globalDebug, globalDumpTraffic, globalLogFile)
		_ = zapLogger // logger is set globally via zap.ReplaceGlobals

		if err := rejectCIOutputFlag(); err != nil {
			return err
		}

		// A broken default config stops every command that would act on it;
		// only the commands that inspect or repair it keep running on defaults.
		clicommon.DiscoveredConfigFatal = discoveredConfigFatal(cmd)

		// Applied before anything can open a database. --read-only is refused on
		// commands that exist to write, rather than silently ignored there: a
		// flag that looks like a safety control and does nothing is worse than
		// one that is absent.
		if err := applyReadOnlyMode(cmd); err != nil {
			return err
		}

		// Now that zero means "no deadline", a negative value is the only
		// remaining way to express something the flag cannot do — reject it
		// rather than let ReadBounded quietly fold it into "no deadline" too.
		if err := validateInputReadTimeout(cmd); err != nil {
			return err
		}

		// --scope-origin is bound on several commands (scan, scan-url, ingest,
		// …); an unknown value used to admit every host.
		if err := validateScopeOrigin(globalScopeOrigin); err != nil {
			return err
		}

		// --color auto|always|never (--no-color = never). Auto colors only when
		// stdout and stderr are both terminals; machine modes force never. The -P
		// parent passes --color=always to its children so their captured
		// console.log keeps its color. See output_hygiene.go.
		if err := applyColorFlag(cmd); err != nil {
			return err
		}

		// The banner goes out here, after parsing, on stderr — not from main()
		// before cobra has seen the command line. See banner.go for what the old
		// pre-parse argv scan got wrong and why stderr is the fix rather than a
		// longer exclusion list.
		printRootBanner(cmd)

		// The olium agent runtime (providers/engine) doesn't log through zap,
		// so --debug alone shows nothing for agent commands. Bridge it to the
		// provider tracing knob so --debug dumps each provider request + SSE
		// stream (credentials scrubbed), matching what the flag advertises.
		if globalDebug || globalDumpTraffic {
			olium.SetDebug(true)
		}

		// Default IS_SANDBOX=1 in vigolium's own env so every child process
		// — the direct anthropic-cli provider, audit's internal claude call,
		// and `vigolium doctor --fix --only claude` — inherits it. Claude
		// Code refuses to run as root unless this is set; vigolium is often
		// invoked from CI/containers where root is the only available user,
		// so opting in by default removes a sharp edge. Only set when unset
		// so a user who explicitly clears it (IS_SANDBOX=) can still do so.
		if _, ok := os.LookupEnv("IS_SANDBOX"); !ok {
			_ = os.Setenv("IS_SANDBOX", "1")
		}

		// Env var fallback for --proxy flag
		if globalProxy == "" {
			globalProxy = os.Getenv("VIGOLIUM_PROXY")
		}

		// Env var fallback for the project selection flags, applied only when
		// neither flag was given (an explicit flag always wins). VIGOLIUM_PROJECT_UUID
		// takes precedence over VIGOLIUM_PROJECT_NAME, mirroring the flag order.
		if globalProjectUUID == "" && globalProjectName == "" {
			if v := os.Getenv("VIGOLIUM_PROJECT_UUID"); v != "" {
				globalProjectUUID = v
				projectFromEnv = true
			} else if v := os.Getenv("VIGOLIUM_PROJECT_NAME"); v != "" {
				globalProjectName = v
				projectFromEnv = true
			}
		}

		// Mutual exclusivity check
		if globalProjectUUID != "" && globalProjectName != "" {
			return usageErrorf("--project-uuid and --project-name are mutually exclusive")
		}

		// -S on server/ingest used to mean --scan-on-receive; it is now a usage
		// error naming the replacement. Before applyDBPathEnv, so a rejected
		// command line never touches a database.
		if err := rejectRetiredScanOnReceive(cmd); err != nil {
			return err
		}

		// Env var fallback for --db (and -S on the read commands), so a shell
		// can be pinned to one session database.
		if err := applyDBPathEnv(cmd); err != nil {
			return err
		}

		// After applyDBPathEnv, so a $VIGOLIUM_DB_PATH pin is already folded into
		// globalDB and one check covers both ways of pinning a source.
		applySourceMustExist(cmd)

		// After the -S folding above, so the warning reflects the resolved flag
		// state rather than the raw command line.
		warnNoOpStateless(cmd)

		// Initialize Vigolium on first run, for the commands that have a reason
		// to need it. `version`, `help`, `completion` and the hidden completion
		// RPCs are excluded: see shouldBootstrap for why a tab-completion must
		// not create a database.
		// -S on a scan-driving command: no config/state written to $HOME. The
		// bootstrap (config, database, presets) is skipped — the scan runs on
		// embedded defaults and profiles — and every state path redirects to a
		// per-process scratch directory (internal/paths).
		if err := applyStatelessHome(cmd); err != nil {
			return err
		}

		if shouldBootstrap(cmd) {
			if !paths.Stateless() {
				if err := ensureInitialized(); err != nil {
					return err
				}
			}
			// --skip-dependency-check opts out of the first-run chromium +
			// nuclei-templates check entirely: stamp the marker now so this and
			// every future scan fast-path past it. Nearly a no-op since the
			// check stopped installing (it only silences the one-line notice);
			// kept for compatibility.
			if globalSkipDependencyCheck {
				if skipCoreDepCheck() {
					fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
						terminal.BoldCyan("Skipping dependency check (--skip-dependency-check) — stamped ~/.vigolium/initialized"))
				}
			} else if needsCoreDeps(cmd) {
				// For commands that drive a native scan, check (never install)
				// the core scan dependencies and say once on stderr what a
				// --spider or known-issue scan will fetch lazily. The phases
				// provision them, outside their budgets, with scan.setup events.
				if err := ensureCoreDeps(coreDepNoticeQuiet(cmd)); err != nil {
					return err
				}
			}
		}

		// Set a soft heap ceiling (GOMEMLIMIT) for scan-driving commands so the
		// Go GC reclaims aggressively near the limit instead of letting the heap
		// grow until the Linux OOM-killer hard-kills the process. Auto-sized
		// from machine RAM and the -P fan-out; the parent exports GOMEMLIMIT so
		// each isolated child scan process inherits the same ceiling.
		applyScanMemLimit(cmd)

		// Check npm for a newer release (cached to once/day). Either schedules a
		// notice printed at the end of the run or, when VIGOLIUM_AUTO_UPDATE is
		// set, silently updates and re-execs the new binary to continue. Honors
		// VIGOLIUM_DISABLE_UPDATE_CHECK and stays silent under --json/CI/non-TTY.
		maybeCheckForUpdate(cmd)

		// After the update check, which may re-exec this process: a pipe drained
		// into a spool file before the re-exec would be empty for the new image.
		// See input_spool.go.
		if err := spoolNonRegularInputs(cmd); err != nil {
			return err
		}

		// Handle -M/--list-modules shortcut
		if globalListModules {
			if err := listModulesShortcut(); err != nil {
				return err
			}
			if !globalJSON {
				fmt.Println()
			}
			os.Exit(0)
		}

		// Handle --list-input-mode shortcut
		if globalListInputModes {
			printInputModes()
			os.Exit(0)
		}

		// Handle --full-example shortcut
		if globalFullExample {
			printFullExamples()
			os.Exit(0)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Show help when no subcommand is given
		return cmd.Help()
	},
}

func init() {
	// Color the "Error:" prefix red for all cobra error messages
	rootCmd.SetErrPrefix(terminal.ErrorPrefix())

	// Suggest the closest registered flag on a mistyped one (e.g. --module →
	// --modules). Set once on root; every subcommand inherits it via
	// FlagErrorFunc()'s walk to the parent.
	rootCmd.SetFlagErrorFunc(flagErrorFunc)

	pf := rootCmd.PersistentFlags()
	registerReadOnlyFlag(rootCmd)
	registerJSONLegacyKeysFlag(rootCmd)

	pf.BoolVarP(&globalVerbose, "verbose", "v", false, "Enable verbose logging output")
	pf.BoolVar(&globalSilent, "silent", false, "Suppress all output except findings")
	pf.BoolVar(&globalDebug, "debug", false, "Enable debug-level logging (includes outgoing HTTP request lines)")
	pf.BoolVar(&globalDumpTraffic, "dump-traffic", false, "Print every HTTP request/response pair to stderr (Burp-style, bypasses logger)")
	pf.StringVar(&globalLogFile, "log-file", "", "Write all log output to this file (JSON format)")
	pf.BoolVarP(&globalJSON, "json", "j", false, "Emit machine-readable JSON for agent/programmatic use (compact bodies; pair with --fields/--compact/--full-body on finding/traffic/db). For the bulk {type,data} stream use --format jsonl / export.")
	pf.StringVar(&globalConfig, "config", "", `Path to config file (default "~/.vigolium/vigolium-configs.yaml")`)
	pf.StringVar(&globalProxy, "proxy", "", "Route all requests through this proxy (HTTP/SOCKS5 URL)")
	pf.BoolVar(&globalOffline, "offline", false, "Keep off every network path that is not the target: no OAST callbacks, third-party lookups (npm registry), nuclei template clone/update, browser download or update check (also settings key offline)")
	pf.StringVar(&globalDB, "db", "", `Path to SQLite database file (default "~/.vigolium/database-vgnm.sqlite"). Also honors $VIGOLIUM_DB_PATH, which additionally reads that file with project scoping off`)
	pf.StringVar(&globalMemLimit, "mem-limit", "", "Soft heap ceiling (GOMEMLIMIT) for scans: empty = auto (1/3 of RAM, scaled down by -P/--parallel so all children stay under ⅔ of RAM), 'off' to disable, or an explicit size/percent like 6GiB or 50%. An existing GOMEMLIMIT env var overrides this.")

	pf.BoolVarP(&globalListModules, "list-modules", "M", false, "List all available scanner modules")
	pf.BoolVar(&globalListInputModes, "list-input-mode", false, "List all supported input modes with examples")
	pf.BoolVar(&globalForce, "force", false, "Skip confirmation prompts")
	pf.BoolVar(&globalSkipDependencyCheck, "skip-dependency-check", false, "Skip the first-run dependency check and stamp ~/.vigolium/initialized (the check only prints a notice; chromium and nuclei templates are fetched by the phase that needs them)")
	pf.BoolVar(&globalSoftFail, "soft-fail", false, "Always exit 0, even when a command fails (error is still printed to stderr; keeps wrapping scripts/CI from being interrupted)")
	pf.IntVar(&globalWidth, "width", 70, "Maximum column width for table output")
	registerStatelessRootFlag(rootCmd)

	pf.StringVar(&globalScanUUID, "scan-uuid", "", "Pin scan UUID for this session (use to sync results across nodes; defaults to a freshly-minted UUID)")
	pf.StringVar(&globalFormat, "format", "console", "Output format (comma-separated for multiple): "+output.FormatsHelp(output.SurfaceScan))
	pf.BoolVar(&globalCIOutput, "ci-output-format", false, "Removed: use -j for the scan document or --format jsonl for the findings stream")
	_ = pf.MarkHidden("ci-output-format")
	pf.BoolVar(&globalNoColor, "no-color", false, "Disable ANSI color in all output (same as --color=never; also honored via the NO_COLOR env var)")
	registerOutputHygieneFlags(pf)
	pf.BoolVar(&globalFullExample, "full-example", false, "Show full example commands organized by section")
	pf.BoolVar(&globalUsage, "usage", false, "Print this command's flags, one line each, and exit (-j: the 'schema flags' document)")
	pf.StringArrayVar(&globalExtScripts, "ext", nil, "Load JavaScript extension script (repeatable)")
	pf.StringVar(&globalExtDir, "ext-dir", "", "Override extension scripts directory")
	pf.BoolVar(&globalExtAllowFailures, "ext-allow-failures", false, "Scan even when an extension named with --ext fails to load (default: abort before any traffic, exit 2 extension_load_failed)")
	pf.StringVar(&globalProjectUUID, "project-uuid", "", "Project to scope all operations to: a UUID, an exact name, or a unique 8+ char UUID prefix of an existing project (defaults to the default project; an unknown one is project_not_found). Also honors $VIGOLIUM_PROJECT_UUID")
	pf.StringVar(&globalProjectName, "project-name", "", "Project name to scope all operations to (must match exactly one project). Also honors $VIGOLIUM_PROJECT_NAME")
}

// memLimitCommands are the command paths (not leaf names: `extensions run` is
// not `run`) that drive a native scan and so get an auto soft heap ceiling. The
// long-running server and the ingest proxy are intentionally excluded — they
// manage their own concurrency and lifetime.
var memLimitCommands = map[string]bool{
	"scan":            true,
	"scan-url":        true,
	"scan-request":    true,
	"run":             true,
	"agent autopilot": true,
	"agent swarm":     true,
}

// applyScanMemLimit derives and applies the GOMEMLIMIT soft ceiling for a
// scan-driving command, logging a one-line note unless output is suppressed. A
// no-op for other commands and for child processes that already inherited a
// GOMEMLIMIT from the -P parent.
func applyScanMemLimit(cmd *cobra.Command) {
	if !memLimitCommands[commandPathWithoutRoot(cmd)] {
		return
	}
	res := memlimit.Apply(memlimit.Options{
		Override:    globalMemLimit,
		Parallelism: globalParallel,
	})
	// Stash the result rather than printing it here. The scan banner replays it
	// right after the logo, but only under a parallel fan-out (-P > 1) — a single
	// scan rarely needs a heap-ceiling line of its own. See printScanSummary.
	scanHeapCeiling = res
}

// prepareCommandTree applies the mutations that need the finished command tree
// (every init() has registered its subcommands). Execute and the tests that
// inspect or parse against the tree share it, so a test sees exactly the flags
// and help text the binary has. Safe to call more than once.
func prepareCommandTree(root *cobra.Command) {
	// Give every command that lacks one a local -S/--stateless, so the letter
	// means one thing across the whole surface. Done here rather than in init:
	// it walks the finished command tree, and every subcommand must already be
	// registered for the walk to reach it.
	addStatelessShorthand(root)

	// kit's subcommands register from their own files' init(), after kit.go's,
	// so its summary can only be derived once the tree is complete.
	deriveKitShort()

	// Stamp each command's declared -j output kind from the central table
	// (machine_kinds.go); machine_contract_test.go checks the result.
	applyMachineKinds(root)

	// Stamp each command's declared database intent (db_intent.go): read
	// commands open the query_only pool, never the write lock.
	applyDBIntentAnnotations(root)

	// A group answers an unknown subcommand with a usage error, and every
	// positional-argument error exits 2 (command_tree_hooks.go). The group hook
	// runs first so its validators are wrapped too.
	enforceGroupSubcommands(root)
	wrapArgsValidators(root)

	// Flags with a closed value set reject a typo while flags parse
	// (enum_flags.go).
	applyClosedValueFlags(root)
}

func Execute() {
	prepareCommandTree(rootCmd)

	// Claim the scratch directory for the whole process, not per scan runner.
	//
	// Plenty of commands that never build a runner still allocate scratch —
	// `export --format pdf`, `db import`, `agent audit -S`, the parallel scan
	// fan-out. Acquiring in the runner left those provisioning a process
	// directory nobody held, so a clean run leaked an empty one every time; and
	// in server mode the count legitimately reached zero between scans, which
	// made Release remove a directory the next request was about to use. One
	// base reference for the process fixes both, and every command gets the
	// cleanup rather than only scans.
	if err := scratch.Acquire(); err != nil {
		zap.L().Warn("Failed to create scratch directory; temporary files will fall back to the system temp dir", zap.Error(err))
	}

	// --usage is answered before cobra parses anything (usage_compact.go).
	if handled, usageErr := runUsageIfRequested(rootCmd, os.Args[1:]); handled {
		releaseScratch()
		if usageErr == nil {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "%s %v\n", terminal.ErrorPrefix(), usageErr)
		emitJSONError(usageErr, ExitUsageError, rootCmd)
		os.Exit(ExitUsageError)
	}

	// ExecuteC (not Execute) so we get the command that actually ran back —
	// the agent-family setup hint below needs to know which one failed.
	jsonResultDeferred = true
	cmd, err := rootCmd.ExecuteC()

	// Bounded delivery of any scan webhook the command fired (asynchronous
	// POSTs die with the process otherwise). Before every exit path below.
	drainScanWebhooks()

	// A failed agent run is nearly always a provider/credential problem, and
	// the fix always lives on one docs page. Printed before the update notice
	// so the version banner stays last.
	if err != nil && isAgentSetupCommand(cmd) {
		printAgentSetupHint(os.Stderr)
	}

	// Print any pending "new version available" notice last, so it lands at the
	// bottom of the output instead of scrolling away. Runs on both the success
	// and error paths (but before the os.Exit calls below).
	flushUpdateNotice()

	// Every exit from here on is an os.Exit, which does not run defers, so the
	// scratch teardown is called explicitly on each path instead.
	releaseScratch()

	if err == nil {
		// The held -j result (json_outcome.go). Its -o write can still fail,
		// which turns a success into export_failed.
		if code, err := finishJSONOutcome(nil, ExitSuccess, cmd); err != nil {
			os.Exit(processExitCode(code, globalSoftFail))
		}
		return
	}

	if err != nil {
		// When the failure IS the flag parse, cobra never bound the presentation
		// flags, so --json/--silent/--soft-fail are all still at their zero
		// values no matter what the caller typed. Recover them from argv before
		// deciding anything, so `traffic --bad --json` answers the same way
		// `traffic --json --bad` does. See presentation_mode.go.
		resolvePresentationMode(argsForPresentationRecovery())

		err = structureUnknownCommand(cmd, err)
		code := classifyExitCode(err)
		// A flag-parse failure never reaches a RunE, so it cannot be wrapped as a
		// usageError at its source; cobra surfaces it as a plain error from
		// ExecuteC with the command still unresolved. Recognising it here is what
		// keeps "unknown flag" at 2 instead of collapsing into the generic 1.
		if code == ExitError && isFlagParseError(err) {
			code = ExitUsageError
		}

		// A caller that asked for JSON gets JSON on the way out too. Without this
		// a failed -j read produced a plain `✖ Error: …` on stderr and NOTHING on
		// stdout, so a consumer's parse failed for a second, unrelated reason and
		// the actual cause had to be scraped out of prose.
		//
		// This runs BEFORE --soft-fail is applied. Soft-fail is a statement about
		// the exit CODE — "do not abort my pipeline" — not a request to be told
		// nothing: the old order exited 0 here and emitted no object at all, so
		// `--json --soft-fail` reported a silent success for a command that had
		// failed, which is the one outcome a machine caller cannot recover from.
		// The held result document (ok:false plus error beside it), or the
		// error envelope when the command wrote no result.
		code, _ = finishJSONOutcome(err, code, cmd)

		// --soft-fail forces a successful exit code so wrapping scripts and CI
		// pipelines are not aborted by errors the operator considers expected.
		// The structured diagnosis above still describes what actually happened,
		// and its exit_code field reports the code that WOULD have been used.
		os.Exit(processExitCode(code, globalSoftFail))
	}
}

// processExitCode is the status the process actually exits with. --soft-fail
// forces 0 for every outcome, the completed results (3, 4, 5) included: a
// caller that opted out of exit-code gating opted out of all of it.
func processExitCode(code int, softFail bool) int {
	if softFail {
		return ExitSuccess
	}
	return code
}

// releaseScratch removes this process's temporary storage and collects what
// earlier runs were killed before releasing. Called on every exit path from
// Execute, which uses os.Exit and therefore runs no defers.
func releaseScratch() {
	scratch.Release()
	// After the release, so the sweep sees this process's directory already
	// gone rather than skipping it as live.
	scratch.SweepOnce(scratch.DefaultMaxAge)
}

// isFlagParseError recognises the errors cobra/pflag raise for a malformed
// command line. Matched on message prefix because pflag returns bare
// fmt.Errorf values with no sentinel to compare against; the set is small and
// stable, and a miss only means the old exit code (1), never a wrong success.
func isFlagParseError(err error) bool {
	msg := err.Error()
	for _, prefix := range []string{
		"unknown flag",
		"unknown shorthand flag",
		"unknown command",
		"invalid argument",
		"flag needs an argument",
		"bad flag syntax",
		"accepts ",
		"required flag",
	} {
		if strings.HasPrefix(msg, prefix) {
			return true
		}
	}
	return false
}

// resolveModules resolves globalModules patterns and globalModuleTags into exact
// module IDs. When both -m and --module-tag are provided, results are merged (union).
// Returns []string{"all"} when neither is specified.
func resolveModules() []string {
	hasModules := len(globalModules) > 0
	hasTags := len(globalModuleTags) > 0

	if !hasModules && !hasTags {
		return []string{"all"}
	}

	seen := make(map[string]struct{})
	var result []string

	addUnique := func(ids []string) {
		for _, id := range ids {
			if id == "all" {
				return
			}
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				result = append(result, id)
			}
		}
	}

	if hasModules {
		resolved := modules.ResolveModulePatterns(globalModules)
		if len(resolved) == 1 && resolved[0] == "all" {
			if !hasTags {
				return resolved
			}
			// -m all with tags: tags win as additional filter doesn't make sense with "all"
			// just return all
			return resolved
		}
		if len(resolved) == 0 {
			zap.L().Warn("no modules matched the given patterns",
				zap.Strings("patterns", globalModules))
			addUnique(globalModules)
		} else {
			zap.L().Debug("resolved module patterns",
				zap.Strings("patterns", globalModules),
				zap.Strings("resolved", resolved))
			addUnique(resolved)
		}
	}

	if hasTags {
		tagResolved := modules.ResolveModuleTags(globalModuleTags)
		if len(tagResolved) == 0 {
			zap.L().Warn("no modules matched the given tags",
				zap.Strings("tags", globalModuleTags))
			// Carried through verbatim, like an unmatched -m pattern: the
			// selection then names no built-in module, and the runner (after
			// matching extensions) or the direct path rejects it. Falling back
			// to every module turned a typo into a full scan.
			unmatched := make([]string, 0, len(globalModuleTags))
			for _, t := range globalModuleTags {
				unmatched = append(unmatched, "tag:"+t)
			}
			addUnique(unmatched)
		} else {
			zap.L().Debug("resolved module tags",
				zap.Strings("tags", globalModuleTags),
				zap.Int("matched", len(tagResolved)))
			addUnique(tagResolved)
		}
	}

	if len(result) == 0 {
		return []string{"all"}
	}
	return result
}

// syncLogger should be deferred in RunE functions to flush buffered logs.
func syncLogger() {
	clicommon.SyncLogger()
}

// configRepairCommands are the command paths that still run (on built-in
// defaults, with a warning) when the discovered config is unreadable: the
// commands an operator uses to find and fix it.
var configRepairCommands = map[string]bool{
	"doctor":          true,
	"config validate": true,
	"config clean":    true,
	"config ls":       true,
	"version":         true,
	"help":            true,
	"completion":      true,
}

// discoveredConfigFatal reports whether an unreadable discovered config must
// fail cmd (clicommon.DiscoveredConfigFatal).
func discoveredConfigFatal(cmd *cobra.Command) bool {
	if cmd == nil {
		return true
	}
	path := strings.TrimSpace(strings.TrimPrefix(cmd.CommandPath(), cmd.Root().Name()))
	for p := path; p != ""; {
		if configRepairCommands[p] {
			return false
		}
		i := strings.LastIndex(p, " ")
		if i < 0 {
			break
		}
		p = p[:i]
	}
	// cobra's hidden completion RPCs.
	return !strings.HasPrefix(cmd.Name(), "__complete")
}

// statelessHomeCommands are the scan-driving command paths on which -S means
// "write nothing to $HOME" (the read commands' -S only switches the store).
var statelessHomeCommands = map[string]bool{
	"scan":         true,
	"run":          true,
	"scan-url":     true,
	"scan-request": true,
}

// applyStatelessHome enables the stateless home (internal/paths) for a -S
// scan, rooted in this process's scratch directory.
func applyStatelessHome(cmd *cobra.Command) error {
	if !globalStateless || cmd == nil {
		paths.EnableStateless("")
		return nil
	}
	top := cmd
	for top.Parent() != nil && top.Parent() != cmd.Root() {
		top = top.Parent()
	}
	if !statelessHomeCommands[top.Name()] {
		return nil
	}
	dir, err := scratch.MkdirTemp("stateless-home-*")
	if err != nil {
		return fmt.Errorf("stateless (-S): cannot create a scratch home: %w", err)
	}
	paths.EnableStateless(dir)
	return nil
}
