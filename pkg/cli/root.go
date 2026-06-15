package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/memlimit"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/olium"
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
	globalTargetFile              string
	globalInputMode               string
	globalInputReadTimeout        time.Duration
	globalTimeout                 time.Duration
	globalConcurrency             int
	globalScanOnReceive           bool
	globalFullNativeScanOnReceive bool
	globalMaxPerHost              int
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

	// Scanning pace override
	globalScanningMaxDuration time.Duration

	// Output format
	globalFormat   string
	globalCIOutput bool
	globalNoColor  bool

	// Full example flag
	globalFullExample bool

	// On-demand extension loading
	globalExtScripts []string // --ext
	globalExtDir     string   // --ext-dir

	// Stateless mode
	globalStateless   bool
	globalSplitByHost bool
	globalDBIsolate   bool
	globalParallel    int

	// Memory ceiling (GOMEMLIMIT)
	globalMemLimit string

	// Request clustering
	globalNoClustering bool

	// Multi-tenancy
	globalProjectUUID string
	globalProjectName string
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
  • vigolium db          — inspect, export, or prune stored data
  • vigolium project     — manage multi-tenant projects

Run 'vigolium <command> --help' for command-specific flags and examples, or 'vigolium --full-example' for a curated tour.`,
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logger for all commands
		zapLogger := initLogger(globalVerbose, globalSilent, globalDebug, globalDumpTraffic, globalLogFile)
		_ = zapLogger // logger is set globally via zap.ReplaceGlobals

		// Color is on by default for every command — including output captured to
		// a file or pipe, such as the -P/--parallel fan-out's per-host
		// <output>.console.log, which should read like a live console scan instead
		// of losing its color the moment stdout isn't a TTY. --no-color,
		// --ci-output-format (CI wants plain logs), and the NO_COLOR env var opt
		// back out; the -P parent forwards --no-color to each child and children
		// inherit NO_COLOR via the environment, so the opt-out reaches every log.
		terminal.EnableCLIColor(globalNoColor, globalCIOutput)

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

		// Env var fallback for --project-uuid flag
		if globalProjectUUID == "" {
			if v := os.Getenv("VIGOLIUM_PROJECT_UUID"); v != "" {
				globalProjectUUID = v
			} else if v := os.Getenv("VIGOLIUM_PROJECT"); v != "" {
				globalProjectUUID = v
			}
		}

		// Mutual exclusivity check
		if globalProjectUUID != "" && globalProjectName != "" {
			return fmt.Errorf("--project-uuid and --project-name are mutually exclusive")
		}

		// Initialize Vigolium on first run (skip when `init` is invoked explicitly)
		if cmd.Name() != "init" {
			if err := ensureInitialized(); err != nil {
				return err
			}
			// --skip-dependency-check opts out of the first-run chromium +
			// nuclei-templates check entirely: stamp the marker now so this and
			// every future scan fast-path past the diagnostic. Applies to any
			// command so users can pre-seed the marker (e.g. in CI) ahead of a
			// scan without triggering a chrome download.
			if globalSkipDependencyCheck {
				if skipCoreDepCheck() {
					fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(),
						terminal.BoldCyan("Skipping dependency check (--skip-dependency-check) — stamped ~/.vigolium/initialized"))
				}
			} else if needsCoreDeps(cmd) {
				// For commands that drive a native scan, guarantee the core
				// scan dependencies (chromium + nuclei templates) are installed
				// before handing control to the command. Cheap/informational
				// commands skip this so they don't trigger a chrome download.
				if err := ensureCoreDeps(); err != nil {
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

		// Handle -M/--list-modules shortcut
		if globalListModules {
			printModuleTable(moduleOpts, "")
			fmt.Println()
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

	pf := rootCmd.PersistentFlags()

	pf.BoolVarP(&globalVerbose, "verbose", "v", false, "Enable verbose logging output")
	pf.BoolVar(&globalSilent, "silent", false, "Suppress all output except findings")
	pf.BoolVar(&globalDebug, "debug", false, "Enable debug-level logging (includes outgoing HTTP request lines)")
	pf.BoolVar(&globalDumpTraffic, "dump-traffic", false, "Print every HTTP request/response pair to stderr (Burp-style, bypasses logger)")
	pf.StringVar(&globalLogFile, "log-file", "", "Write all log output to this file (JSON format)")
	pf.BoolVarP(&globalJSON, "json", "j", false, "Emit machine-readable JSON for agent/programmatic use (compact bodies; pair with --fields/--compact/--full-body on finding/traffic/db). For the bulk {type,data} stream use --format jsonl / export.")
	pf.StringVar(&globalConfig, "config", "", `Path to config file (default "~/.vigolium/vigolium-configs.yaml")`)
	pf.StringVar(&globalProxy, "proxy", "", "Route all requests through this proxy (HTTP/SOCKS5 URL)")
	pf.StringVar(&globalDB, "db", "", `Path to SQLite database file (default "~/.vigolium/database-vgnm.sqlite")`)
	pf.StringVar(&globalMemLimit, "mem-limit", "", "Soft heap ceiling (GOMEMLIMIT) for scans: empty = auto (~⅓ of RAM, scaled down by -P/--parallel so all children stay under ⅔ of RAM), 'off' to disable, or an explicit size/percent like 6GiB or 50%. An existing GOMEMLIMIT env var overrides this.")

	pf.BoolVarP(&globalListModules, "list-modules", "M", false, "List all available scanner modules")
	pf.BoolVar(&globalListInputModes, "list-input-mode", false, "List all supported input modes with examples")
	pf.BoolVarP(&globalForce, "force", "F", false, "Skip confirmation prompts")
	pf.BoolVar(&globalSkipDependencyCheck, "skip-dependency-check", false, "Skip the first-run dependency check (chromium, nuclei templates) and stamp ~/.vigolium/initialized immediately")
	pf.BoolVar(&globalSoftFail, "soft-fail", false, "Always exit 0, even when a command fails (error is still printed to stderr; keeps wrapping scripts/CI from being interrupted)")
	pf.IntVar(&globalWidth, "width", 70, "Maximum column width for table output")

	pf.StringVar(&globalScanUUID, "scan-uuid", "", "Pin scan UUID for this session (use to sync results across nodes; defaults to a freshly-minted UUID)")
	pf.StringVar(&globalFormat, "format", "console", "Output format (comma-separated for multiple): console, jsonl, html")
	pf.BoolVar(&globalCIOutput, "ci-output-format", false, "CI-friendly output: JSONL findings only, no color, no banners")
	pf.BoolVar(&globalNoColor, "no-color", false, "Disable ANSI color in all output (also honored via the NO_COLOR env var)")
	pf.BoolVar(&globalFullExample, "full-example", false, "Show full example commands organized by section")
	pf.StringArrayVar(&globalExtScripts, "ext", nil, "Load JavaScript extension script (repeatable)")
	pf.StringVar(&globalExtDir, "ext-dir", "", "Override extension scripts directory")
	pf.StringVar(&globalProjectUUID, "project-uuid", "", "Project UUID to scope all operations to (defaults to the default project)")
	pf.StringVar(&globalProjectName, "project-name", "", "Project name to scope all operations to (must match exactly one project)")
}

// memLimitCommands are the leaf command names that drive a native scan and so
// get an auto soft heap ceiling. The long-running server and the ingest proxy
// are intentionally excluded — they manage their own concurrency and lifetime.
var memLimitCommands = map[string]bool{
	"scan":         true,
	"scan-url":     true,
	"scan-request": true,
	"run":          true,
	"autopilot":    true, // `vigolium agent autopilot`
	"swarm":        true, // `vigolium agent swarm`
}

// applyScanMemLimit derives and applies the GOMEMLIMIT soft ceiling for a
// scan-driving command, logging a one-line note unless output is suppressed. A
// no-op for other commands and for child processes that already inherited a
// GOMEMLIMIT from the -P parent.
func applyScanMemLimit(cmd *cobra.Command) {
	if !memLimitCommands[cmd.Name()] {
		return
	}
	res := memlimit.Apply(memlimit.Options{
		Override:    globalMemLimit,
		Parallelism: globalParallel,
	})
	if res.Note != "" && !globalSilent && !globalCIOutput {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.InfoSymbol(), res.Note)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Cobra has already printed the error to stderr. --soft-fail forces a
		// successful exit code so wrapping scripts/CI pipelines aren't aborted
		// by errors the operator considers expected. The persistent flag is
		// bound during Execute()'s arg parsing, so its value is populated here
		// for every error except a flag-parse failure (which stays non-zero).
		if globalSoftFail {
			os.Exit(0)
		}
		os.Exit(1)
	}
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
