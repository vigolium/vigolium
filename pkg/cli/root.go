package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Global flags shared across all commands
var (
	globalVerbose              bool
	globalSilent               bool
	globalDebug                bool
	globalDumpTraffic          bool
	globalLogFile              string
	globalJSON                 bool
	globalConfig               string
	globalProxy                string
	globalDB                   string
	globalTargets              []string
	globalTargetFile           string
	globalInputMode            string
	globalInputReadTimeout     time.Duration
	globalTimeout              time.Duration
	globalConcurrency          int
	globalScanOnReceive        bool
	globalMaxPerHost           int
	globalMaxHostError         int
	globalMaxFindingsPerModule int
	globalListModules          bool
	globalListInputModes       bool
	globalForce                bool
	globalDisableFetchResponse bool
	globalWidth                int

	// Input / server / module flags (shared by scan, ingest, etc.)
	globalInput      string
	globalRateLimit  int
	globalModules    []string
	globalModuleTags []string
	globalScanID      string
	globalSpecURL     bool
	globalSpecHeader  []string
	globalSpecVar     []string
	globalSpecDefault string

	// Source code awareness
	globalSourcePath string

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

	// Watch mode: re-run queries at interval
	globalWatchRaw string

	// Scope origin mode
	globalScopeOrigin string

	// Scanning pace override
	globalScanningMaxDuration time.Duration

	// Output format
	globalFormat string

	// Full example flag
	globalFullExample bool

	// On-demand extension loading
	globalExtScripts []string // --ext
	globalExtDir     string   // --ext-dir

	// Request clustering
	globalNoClustering bool

	// Multi-tenancy
	globalProject string
)

var rootCmd = &cobra.Command{
	Use:   "vigolium",
	Short: "High-fidelity web vulnerability scanner",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize logger for all commands
		zapLogger := initLogger(globalVerbose, globalSilent, globalDebug, globalDumpTraffic, globalLogFile)
		_ = zapLogger // logger is set globally via zap.ReplaceGlobals

		// Env var fallback for --proxy flag
		if globalProxy == "" {
			globalProxy = os.Getenv("VIGOLIUM_PROXY")
		}

		// Env var fallback for --project flag
		if globalProject == "" {
			globalProject = os.Getenv("VIGOLIUM_PROJECT")
		}

		// Initialize Vigolium on first run
		if err := ensureInitialized(); err != nil {
			return err
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
	pf.BoolVar(&globalDebug, "debug", false, "Dump raw HTTP request and response traffic")
	pf.BoolVar(&globalDumpTraffic, "dump-traffic", false, "Print every HTTP request/response pair to stderr (Burp-style debug output)")
	pf.StringVar(&globalLogFile, "log-file", "", "Write all log output to this file (JSON format)")
	pf.BoolVarP(&globalJSON, "json", "j", false, "Format output as JSON")
	pf.StringVar(&globalConfig, "config", "", `Path to config file (default "~/.vigolium/vigolium-configs.yaml")`)
	pf.StringVar(&globalProxy, "proxy", "", "Proxy URL for sending requests (HTTP/SOCKS5)")
	pf.StringVar(&globalDB, "db", "", `Path to SQLite database file (default "~/.vigolium/database-vgnm.sqlite")`)

	pf.StringSliceVarP(&globalTargets, "target", "t", nil, "Target URL to scan (can be specified multiple times)")
	pf.StringVarP(&globalTargetFile, "target-file", "T", "", "File containing list of target URLs")
	pf.StringVarP(&globalInputMode, "input-mode", "I", "urls", "Input spec format (--list-input-mode for all)")
	pf.DurationVar(&globalInputReadTimeout, "input-read-timeout", 3*time.Minute, "Timeout for reading input from stdin or file")
	pf.DurationVar(&globalTimeout, "timeout", 15*time.Second, "HTTP request timeout (e.g. 30s, 1m, 2h)")
	pf.IntVarP(&globalConcurrency, "concurrency", "c", 50, "Number of concurrent scan workers")
	pf.IntVar(&globalMaxPerHost, "max-per-host", 2, "Maximum concurrent requests allowed per host")
	pf.IntVar(&globalMaxHostError, "max-host-error", 30, "Skip host after reaching this many consecutive errors")
	pf.IntVar(&globalMaxFindingsPerModule, "max-findings-per-module", 15, "Suppress findings after this many per module (0 = unlimited)")
	pf.BoolVarP(&globalScanOnReceive, "scan-on-receive", "S", false, "Watch database for new HTTP records and scan them automatically")
	pf.BoolVarP(&globalListModules, "list-modules", "M", false, "List all available scanner modules")
	pf.BoolVar(&globalListInputModes, "list-input-mode", false, "List all supported input modes with examples")
	pf.BoolVarP(&globalForce, "force", "F", false, "Skip confirmation prompts for destructive operations")
	pf.BoolVar(&globalDisableFetchResponse, "disable-fetch-response", false, "Skip fetching HTTP responses during ingestion (store request-only)")
	pf.IntVar(&globalWidth, "width", 70, "Maximum column width for table output")

	// Input / server / module flags
	pf.StringVarP(&globalInput, "input", "i", "-", "Input spec or file path (- for stdin)")
	pf.IntVarP(&globalRateLimit, "rate-limit", "r", 100, "Maximum request submissions per second")
	pf.StringSliceVarP(&globalModules, "modules", "m", nil, `Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli)`)
	pf.StringSliceVar(&globalModuleTags, "module-tag", nil, `Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection)`)
	pf.StringVar(&globalScanID, "scan-id", "", "Label to group all findings and records from this scan session (use with db list/stats/export/clean to filter by session)")
	pf.BoolVar(&globalSpecURL, "spec-url", false, "Use server URLs defined in the OpenAPI spec")
	pf.StringSliceVar(&globalSpecHeader, "spec-header", nil, "HTTP header for OpenAPI requests (can be specified multiple times)")
	pf.StringSliceVar(&globalSpecVar, "spec-var", nil, "OpenAPI parameter value as key=value (can be specified multiple times)")
	pf.StringVar(&globalSpecDefault, "spec-default", "1", "Default value for required parameters without examples")
	pf.StringVar(&globalSourcePath, "source", "", "Local path to application source code for source-aware scanning")
	pf.StringVar(&scanOpts.SourceURL, "source-url", "", "Git URL to clone for source-aware scanning")
	pf.StringVar(&globalOnly, "only", "", "Run only a single phase: ingestion, discover, external-harvest, spa, or dynamic-assessment")
	pf.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip one or more phases: discover, external-harvest, spidering, spa, sast, dynamic-assessment")
	pf.StringVar(&globalStrategy, "strategy", "", "Scanning strategy preset (lite, balanced, deep, whitebox)")
	pf.StringVar(&globalScanningProfile, "scanning-profile", "", "Scanning profile YAML (name from profiles_dir or path)")
	pf.StringVar(&globalWatchRaw, "watch", "", "Re-run the command at the specified interval (e.g. 5, 10s, 1m, 1h)")
	pf.StringVar(&globalScopeOrigin, "scope-origin", "", "Origin scope mode: all, relaxed, balanced, strict")
	pf.DurationVar(&globalScanningMaxDuration, "scanning-max-duration", 0, "Override scanning_pace.max_duration (e.g. 1h, 2h, 30m)")
	pf.StringVar(&globalFormat, "format", "console", "Output format: console, jsonl, html")
	pf.StringVar(&globalHeuristicsCheck, "heuristics-check", "", `Heuristics check level: none, basic, advanced (default "basic")`)
	pf.BoolVar(&globalSkipHeuristics, "skip-heuristics", false, "Skip heuristics check (shortcut for --heuristics-check=none)")
	pf.BoolVar(&globalFullExample, "full-example", false, "Show full example commands organized by section")
	pf.StringArrayVar(&globalExtScripts, "ext", nil, "Extension script path to load (can repeat; added on top of config)")
	pf.StringVar(&globalExtDir, "ext-dir", "", "Override extension scripts directory")
	pf.BoolVar(&globalNoClustering, "no-clustering", false, "Disable request clustering (deduplication of concurrent identical HTTP requests)")
	pf.StringVar(&globalProject, "project", "", "Project UUID to scope all operations to (defaults to the default project)")
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
