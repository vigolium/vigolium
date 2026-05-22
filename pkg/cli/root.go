package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/modules"
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

	// Full example flag
	globalFullExample bool

	// On-demand extension loading
	globalExtScripts []string // --ext
	globalExtDir     string   // --ext-dir

	// Stateless mode
	globalStateless bool

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
			// For commands that drive a native scan, also guarantee the core
			// scan dependencies (chromium + nuclei templates) are installed
			// before handing control to the command. Cheap/informational
			// commands skip this so they don't trigger a chrome download.
			if needsCoreDeps(cmd) {
				if err := ensureCoreDeps(); err != nil {
					return err
				}
			}
		}

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
	pf.BoolVarP(&globalJSON, "json", "j", false, "Format output as JSONL (one JSON object per line)")
	pf.StringVar(&globalConfig, "config", "", `Path to config file (default "~/.vigolium/vigolium-configs.yaml")`)
	pf.StringVar(&globalProxy, "proxy", "", "Route all requests through this proxy (HTTP/SOCKS5 URL)")
	pf.StringVar(&globalDB, "db", "", `Path to SQLite database file (default "~/.vigolium/database-vgnm.sqlite")`)

	pf.BoolVarP(&globalListModules, "list-modules", "M", false, "List all available scanner modules")
	pf.BoolVar(&globalListInputModes, "list-input-mode", false, "List all supported input modes with examples")
	pf.BoolVarP(&globalForce, "force", "F", false, "Skip confirmation prompts")
	pf.IntVar(&globalWidth, "width", 70, "Maximum column width for table output")

	pf.StringVar(&globalScanUUID, "scan-uuid", "", "Pin scan UUID for this session (use to sync results across nodes; defaults to a freshly-minted UUID)")
	pf.StringVar(&globalFormat, "format", "console", "Output format (comma-separated for multiple): console, jsonl, html")
	pf.BoolVar(&globalCIOutput, "ci-output-format", false, "CI-friendly output: JSONL findings only, no color, no banners")
	pf.BoolVar(&globalFullExample, "full-example", false, "Show full example commands organized by section")
	pf.StringArrayVar(&globalExtScripts, "ext", nil, "Load JavaScript extension script (repeatable)")
	pf.StringVar(&globalExtDir, "ext-dir", "", "Override extension scripts directory")
	pf.StringVar(&globalProjectUUID, "project-uuid", "", "Project UUID to scope all operations to (defaults to the default project)")
	pf.StringVar(&globalProjectName, "project-name", "", "Project name to scope all operations to (must match exactly one project)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
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
	_ = zap.L().Sync()
}
