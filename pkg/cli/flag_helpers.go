package cli

import (
	"time"

	"github.com/spf13/pflag"
)

// Flag-registration helpers shared by the scan, run, ingest, scan-url, and
// scan-request commands. They live here (rather than as PersistentFlags on
// the root command) so flags only show up on the commands that actually use
// them — keeping `vigolium db --help` / `project --help` / etc. uncluttered.
//
// The variables themselves stay package-level (defined in root.go) so reads
// from helper code (e.g. resolveModules, ingest opts copying) keep working
// without plumbing.

// registerInputSourceFlags registers the target/input/input-mode set used by
// commands that ingest or scan from external sources.
func registerInputSourceFlags(flags *pflag.FlagSet) {
	flags.StringSliceVarP(&globalTargets, "target", "t", nil, "Target URL to scan (can be specified multiple times)")
	flags.StringVarP(&globalTargetFile, "target-file", "T", "", "File containing target URLs (one per line)")
	flags.StringVarP(&globalInput, "input", "i", "-", "Input file path or spec (use - for stdin)")
	flags.StringVarP(&globalInputMode, "input-mode", "I", "urls", "Input format: urls, openapi, swagger, burp, curl, nuclei, har (see --list-input-mode)")
	flags.DurationVar(&globalInputReadTimeout, "input-read-timeout", 3*time.Minute, "Timeout for reading input from stdin or file")
}

// registerHTTPClientFlags registers the network/concurrency knobs shared by
// every command that makes HTTP requests.
func registerHTTPClientFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&globalTimeout, "timeout", 15*time.Second, "HTTP request timeout (e.g. 30s, 1m, 2h)")
	flags.IntVarP(&globalConcurrency, "concurrency", "c", 50, "Number of concurrent scan workers")
	flags.IntVarP(&globalRateLimit, "rate-limit", "r", 100, "Maximum HTTP requests per second")
	flags.IntVar(&globalMaxPerHost, "max-per-host", 50, "Maximum concurrent requests allowed per host")
	flags.IntVar(&globalMaxHostError, "max-host-error", 30, "Skip host after reaching this many consecutive errors")
	flags.IntVar(&globalMaxFindingsPerModule, "max-findings-per-module", 10, "Stop reporting after N findings per module (0 = unlimited)")
	flags.BoolVar(&globalNoClustering, "no-clustering", false, "Disable deduplication of identical concurrent HTTP requests")
}

// registerScanPipelineFlags registers the phase/strategy/profile knobs that
// only make sense for the full native scan pipeline (scan + run).
func registerScanPipelineFlags(flags *pflag.FlagSet) {
	flags.StringVar(&globalOnly, "only", "", "Run only these phases (comma-separated: ingestion, discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment, extension)")
	flags.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip these phases (repeatable: discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment)")
	flags.StringVar(&globalStrategy, "strategy", "", "Scanning strategy preset (lite, balanced, deep)")
	flags.StringVar(&globalScanningProfile, "scanning-profile", "", "Scanning profile name or YAML file path")
	flags.StringVar(&globalIntensity, "intensity", "", "Scan intensity preset: quick, balanced, or deep (maps to scanning profile + strategy)")
	flags.StringVar(&globalScopeOrigin, "scope-origin", "", "Host scope strictness: all, relaxed, balanced, strict")
	flags.DurationVar(&globalScanningMaxDuration, "scanning-max-duration", 0, "Maximum total scan duration (overrides config, e.g. 1h, 30m)")
	flags.StringVar(&globalHeuristicsCheck, "heuristics-check", "", `Pre-scan heuristics level: none, basic, advanced (default: basic)`)
	flags.BoolVar(&globalSkipHeuristics, "skip-heuristics", false, "Disable pre-scan heuristics (equivalent to --heuristics-check=none)")
}

// registerSpecFlags registers OpenAPI/Swagger spec options shared by scan
// (when -i is an OpenAPI file) and ingest.
func registerSpecFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&globalSpecURL, "spec-url", false, "Use base URLs from the OpenAPI spec's servers field")
	flags.StringSliceVar(&globalSpecHeader, "spec-header", nil, "Add HTTP header to OpenAPI-generated requests (repeatable)")
	flags.StringSliceVar(&globalSpecVar, "spec-var", nil, "Set OpenAPI parameter value as key=value (repeatable)")
	flags.StringVar(&globalSpecDefault, "spec-default", "1", "Fallback value for required OpenAPI parameters that lack examples")
}

// registerScanModuleFlags registers --modules/-m and --module-tag, used by
// every command that filters scanner modules at runtime (scan, run, ingest,
// scan-url, scan-request).
func registerScanModuleFlags(flags *pflag.FlagSet) {
	flags.StringSliceVarP(&globalModules, "modules", "m", nil, `Scan modules to enable (default "all", supports fuzzy match on ID/name, e.g. -m xss -m sqli)`)
	flags.StringSliceVar(&globalModuleTags, "module-tag", nil, `Filter modules by tag (OR condition, e.g. --module-tag spring --module-tag injection)`)
	flags.BoolVar(&globalNoTechFilter, "no-tech-filter", false, "Disable the tech-stack allowlist (run every module regardless of detected stack). Auto-enabled by --intensity=deep.")
}

// registerLightweightScanIOFlags registers the output/persistence/phase-skip
// flags shared by the lightweight single-request commands (scan-url,
// scan-request) so their output surface matches `vigolium scan`'s -o/--output,
// -S/--stateless, and --skip. When any of these (or a file output --format) is
// set, the command routes the request through the full native-scan Runner (see
// runRunnerScan) instead of the in-memory direct path, so the flags produce real
// jsonl/html files and a discarded temp DB exactly like the full scan command.
func registerLightweightScanIOFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&scanOpts.Output, "output", "o", "", "Write findings to this file (use with --format jsonl|html; pairs with -S/--stateless)")
	flags.BoolVarP(&globalStateless, "stateless", "S", false, "Use a temporary database that is discarded after the scan (pass --output/--format to persist results)")
	flags.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip these phases (repeatable: discovery, external-harvest, spidering, known-issue-scan, dynamic-assessment)")
	flags.StringVar(&scanFailOn, "fail-on", "", "Exit non-zero if a finding at or above this severity is present (info|low|medium|high|critical) — for CI/agent gating; --soft-fail overrides.")
}

// markFlagDeprecated hides oldName from --help and makes pflag emit a one-time
// stderr warning ("Flag --<oldName> has been deprecated, use --<replacement>")
// when it is set. Use after registering a hidden alias whose variable is shared
// with the canonical flag.
func markFlagDeprecated(flags *pflag.FlagSet, oldName, replacement string) {
	if f := flags.Lookup(oldName); f != nil {
		f.Deprecated = "use --" + replacement
	}
}
