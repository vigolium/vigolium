package cli

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/input/source"
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
	flags.StringArrayVarP(&globalTargets, "target", "t", nil, "Target URL to scan (repeatable). Commas are literal so a URL query like ?ids=1,2,3 stays one target — repeat -t for multiple targets.")
	flags.StringArrayVarP(&globalTargetFiles, "target-file", "T", nil, "File containing target URLs (one per line; repeatable for multiple files). Commas in the path are literal.")
	flags.StringVarP(&globalInput, "input", "i", "-", "Input file path or spec (use - for stdin)")
	flags.StringVarP(&globalInputMode, "input-mode", "I", "urls", inputModeFlagUsage())
	registerInputReadTimeoutFlag(flags)
}

// inputModeFlagUsage builds the -I help text from the format registry, so a
// format added in pkg/input/source is advertised without a second edit here.
// The hand-written list it replaced had drifted: it offered "swagger" and
// "burp" (aliases) beside canonical names, and omitted postman, burpraw,
// burpscope and deparos entirely.
func inputModeFlagUsage() string {
	return "Input format: " + source.SupportedFormats() + " (aliases accepted, see --list-input-mode)"
}

// registerInputReadTimeoutFlag declares --input-read-timeout. One definition,
// shared by the ingesting commands and the lightweight single-request ones:
// scan-url and scan-request both read stdin and both lacked the dial that
// bounds it.
//
// Enforced by readStdin (see stdin.go). It used to be registered, assigned into
// Options.InputReadTimeout, and read by nothing at all, so a pipe that never
// closed hung the process regardless of what was passed.
func registerInputReadTimeoutFlag(flags *pflag.FlagSet) {
	flags.DurationVar(&globalInputReadTimeout, inputReadTimeoutFlag, defaultInputReadTimeout,
		"Deadline for reading input from stdin; 0 disables it")
}

// registerHTTPClientFlags registers the network/concurrency knobs shared by
// every command that makes HTTP requests.
func registerHTTPClientFlags(flags *pflag.FlagSet) {
	flags.DurationVar(&globalTimeout, "timeout", 15*time.Second, "HTTP request timeout (e.g. 30s, 1m, 2h)")
	registerPaceFlags(flags)
	flags.BoolVar(&globalNoWafPacing, "no-waf-pacing", false, "Disable proactive CDN/WAF-edge pacing (don't pre-throttle per-host concurrency when a CloudFront/Cloudflare/etc. edge is detected); reactive back-off after a WAF block still applies")
	flags.IntVar(&globalMaxHostError, "max-host-error", 30, "Skip host after reaching this many consecutive errors")
	flags.IntVar(&globalMaxFindingsPerModule, "max-findings-per-module", 50, "Stop reporting after N distinct findings per module; drops are counted in the summary and events (0 = unlimited)")
	flags.BoolVar(&globalNoClustering, "no-clustering", false, "Disable deduplication of identical concurrent HTTP requests")
}

// scopeOriginFlagUsage is shared by every command registering --scope-origin
// (scan/run here, ingest in ingest.go). The default is spelled in the text
// because the flag's zero value has to stay "" to distinguish "not passed" from
// an explicit choice, so pflag cannot print it.
const scopeOriginFlagUsage = "Host scope strictness: all, relaxed, balanced, strict (default balanced; balanced admits any host sharing the target's eTLD+1, including subdomains already in the database from earlier scans). Bounds which STORED records a phase works and, under the default --redirect-mode in-scope, which hosts a redirect may follow to"

// registerScanPipelineFlags registers the phase/strategy/profile knobs that
// only make sense for the full native scan pipeline (scan + run).
func registerScanPipelineFlags(flags *pflag.FlagSet) {
	flags.StringVar(&globalOnly, "only", "", "Run only these phases (comma-separated: "+runner.PhaseNamesDesc(false)+"; aliases accepted, see 'vigolium run --help')")
	flags.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip these phases (repeatable: "+runner.PhaseNamesDesc(true)+"; aliases accepted, see 'vigolium run --help')")
	flags.StringVar(&globalStrategy, "strategy", "", "Advanced: which phases run (lite, balanced, deep); --intensity picks this for you")
	flags.StringVar(&globalScanningProfile, "scanning-profile", "", "Advanced: scanning profile name or YAML file path (pace, discovery depth, templates); --intensity picks this for you")
	registerIntensityFlag(flags)
	registerScopeOriginFlag(flags)
	registerScanningMaxDurationFlag(flags)
	flags.StringVar(&globalHeuristicsCheck, "heuristics-check", "", `Pre-scan heuristics level: none, basic, advanced (default: basic)`)
	flags.BoolVar(&globalSkipHeuristics, "skip-heuristics", false, "Disable pre-scan heuristics (equivalent to --heuristics-check=none)")
	registerAllowRiskyPayloadsFlag(flags)
	registerNoParamDedupFlag(flags)
	flags.StringVar(&scanOpts.ResumeScanUUID, "resume-scan", "",
		"Resume a previous scan by UUID: reuse its scan row and cursor and skip the records/modules its coverage ledger records as done")
	flags.StringVar(&scanOpts.HeaderFuzz, "header-fuzz", "",
		"Header insertion points: gated (default: noise headers skipped, logged/negotiation/routing headers once per host and only for the vuln classes they can sink) or all (every header, every module, per path). Overrides config dynamic-assessment.header_points")
	registerParamMiningFlag(flags)
	registerRequestBudgetFlags(flags)
	registerScanDocumentFlags(flags)
}

// registerIntensityFlag, registerScopeOriginFlag and
// registerScanningMaxDurationFlag are the one definition of each flag, shared
// by the full pipeline (registerScanPipelineFlags: scan, run) and the
// lightweight single-request commands (registerLightweightScanTuningFlags:
// scan-url, scan-request). They bind the same globals, so the resolver
// (resolveNativeScanOptions / resolveLightweightScanOptions) reads one value
// whichever command parsed it.
func registerIntensityFlag(flags *pflag.FlagSet) {
	flags.StringVar(&globalIntensity, "intensity", "", "How hard to scan: quick, balanced (default), or deep — the one dial for phases, pace and module tiers (sets --strategy and --scanning-profile)")
}

func registerScopeOriginFlag(flags *pflag.FlagSet) {
	flags.StringVar(&globalScopeOrigin, "scope-origin", "", scopeOriginFlagUsage)
}

// registerScanningMaxDurationFlag declares --max-time (canonical) and its
// alias --scanning-max-duration, bound to one value. Unset, the scan is
// bounded by scanning_pace.scan_max_duration (default 1h; --safe 15m).
func registerScanningMaxDurationFlag(flags *pflag.FlagSet) {
	flags.DurationVar(&globalScanningMaxDuration, "max-time", 0, "Maximum total scan duration, e.g. 15m, 2h (default: scanning_pace.scan_max_duration, 1h; alias --scanning-max-duration)")
	flags.DurationVar(&globalScanningMaxDuration, "scanning-max-duration", 0, "Alias of --max-time")
	_ = flags.MarkHidden("scanning-max-duration")
	registerSafeFlag(flags)
}

// registerSafeFlag declares --safe (scan, run, scan-url, scan-request).
func registerSafeFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&scanOpts.Safe, "safe", false, "Bounded, non-mutating scan: GET/HEAD traffic only, no form submission/uploads/login attempts in the browser, no risky payloads or intrusive templates, low pace, 15m total budget (typed flags still win)")
}

// maxTimeTyped reports whether --max-time or its alias was typed.
func maxTimeTyped(cmd *cobra.Command) bool {
	for _, name := range []string{"max-time", "scanning-max-duration"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return true
		}
	}
	return false
}

// registerOASTURLFlag declares --oast-url for scan, run, scan-url and
// scan-request.
func registerOASTURLFlag(flags *pflag.FlagSet) {
	flags.StringVar(&scanOpts.OastURL, "oast-url", "", "Fixed out-of-band callback URL instead of interactsh; put {nonce} in it (https://{nonce}.cb.example.com) to attribute logged callbacks with 'vigolium oast ingest'")
}

// registerLightweightScanTuningFlags registers the scan-tuning flags scan-url
// and scan-request share with `vigolium scan`: --intensity,
// --scanning-max-duration, --scope-origin, --oast-url and --auth/--auth-file.
// Same globals, same usage strings (pinned by TestScanTuningFlagParity).
//
// Routing: --auth/--auth-file and --intensity need the runner (session
// hydration, profile + module-tier resolution), so they send the request down
// the Runner path (needsRunnerScan). --scanning-max-duration and --oast-url
// are honoured on the direct path too (executor MaxDuration, fixed-URL OAST).
// --scope-origin was read by both paths before it was registered here.
func registerLightweightScanTuningFlags(flags *pflag.FlagSet) {
	registerIntensityFlag(flags)
	registerScanningMaxDurationFlag(flags)
	registerScopeOriginFlag(flags)
	registerOASTURLFlag(flags)
	registerAuthFlags(flags)
}

// registerParamMiningFlag declares --param-mining for the full pipeline (scan,
// run). It binds into scanOpts.ParamMining, left nil when absent so the phase
// follows the intensity (on at deep); an explicit value wins either way.
func registerParamMiningFlag(flags *pflag.FlagSet) {
	f := flags.VarPF(optionalBoolFlag{target: &scanOpts.ParamMining}, "param-mining", "",
		"Mine hidden parameters (Arjun-style) on this scan's dynamic endpoints before the assessment, so injection modules test them too. Default: on at --intensity deep, off below; --param-mining=false turns it off at deep. Budget: dynamic-assessment.param_mining in config")
	f.NoOptDefVal = "true"
}

// registerAllowRiskyPayloadsFlag declares --allow-risky-payloads for the scan
// commands (scan, run via registerScanPipelineFlags; scan-url, scan-request via
// registerLightweightScanIOFlags). It binds straight into
// scanOpts.AllowRiskyPayloads, left nil when the flag is absent so config
// dynamic-assessment.allow_risky_payloads decides; an explicit value (including
// =false) overrides config.
func registerAllowRiskyPayloadsFlag(flags *pflag.FlagSet) {
	f := flags.VarPF(optionalBoolFlag{target: &scanOpts.AllowRiskyPayloads}, "allow-risky-payloads", "",
		"Allow risk:high payloads and modules below --intensity deep (OR-per-row and stacked time-blind SQLi, so MSSQL time-blind; state-changing probes). Always on at deep. Overrides config dynamic-assessment.allow_risky_payloads")
	f.NoOptDefVal = "true"
}

// registerNoParamDedupFlag declares --no-param-dedup for the same scan commands
// as --allow-risky-payloads (scan, run, scan-url, scan-request). It binds into
// scanOpts.NoParamDedup, which the executor mirrors into
// ScanContext.NoParamDedup.
func registerNoParamDedupFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&scanOpts.NoParamDedup, "no-param-dedup", false,
		"Keep testing a parameter with every module of a vuln class after one already reported it (default: one finding per param and class, e.g. sqli-time-blind skips a param sqli-error-based confirmed). For audit runs")
}

// optionalBoolFlag is a bool flag that also records whether it was passed: the
// target stays nil until Set, so an absent flag defers to config while an
// explicit --flag=false still wins over a config true.
type optionalBoolFlag struct{ target **bool }

func (f optionalBoolFlag) String() string {
	if f.target == nil || *f.target == nil {
		return "false"
	}
	return strconv.FormatBool(**f.target)
}

func (f optionalBoolFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*f.target = &v
	return nil
}

func (f optionalBoolFlag) Type() string { return "bool" }

func (f optionalBoolFlag) IsBoolFlag() bool { return true }

// registerSpecFlags registers OpenAPI/Swagger spec options shared by scan
// (when -i is an OpenAPI file) and ingest.
func registerSpecFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&globalSpecURL, "spec-url", false, "Use base URLs from the OpenAPI spec's servers field")
	flags.StringArrayVar(&globalSpecHeader, "spec-header", nil, "Add HTTP header to OpenAPI-generated requests (repeatable; commas are literal)")
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
	registerKeepDBOnErrorFlag(flags)
	registerAllowRiskyPayloadsFlag(flags)
	registerNoParamDedupFlag(flags)
	registerRequestBudgetFlags(flags)
	registerScanDocumentFlags(flags)
	flags.StringSliceVar(&globalSkipPhases, "skip", nil, "Skip these phases (repeatable: "+runner.PhaseNamesDesc(true)+"; aliases accepted, see 'vigolium run --help')")
	flags.StringVar(&scanFailOn, "fail-on", "", failOnUsage("for CI/agent gating; implies --fail-on-partial; --soft-fail overrides."))
	flags.BoolVar(&scanFailOnPartial, "fail-on-partial", false, "Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on")
	registerBaselineFlags(flags)
	flags.BoolVar(&scanPrintFinding, "print-finding", false, "After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick single-target scan.")
	flags.BoolVar(&scanPrintTrafficTree, "print-traffic-tree", false, "After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent.")
	flags.BoolVar(&scanPrintTraffic, "print-traffic", false, "After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent.")
	registerEventsFlag(flags)
	registerReportFlags(flags)
	// scan-url and scan-request read a request from stdin just as scan does,
	// so they get the same deadline dial. Neither registers
	// registerInputSourceFlags, so there is no double registration.
	registerInputReadTimeoutFlag(flags)
}

// registerKeepDBOnErrorFlag declares --keep-db-on-error, for the same reason
// registerEventsFlag exists: it is offered by both the full scan commands and
// the lightweight ones, and two literal registrations are two help texts waiting
// to diverge.
func registerKeepDBOnErrorFlag(flags *pflag.FlagSet) {
	flags.BoolVar(&globalKeepDBOnError, "keep-db-on-error", false,
		"On a failed -S/--stateless scan, move the throwaway working database to ~/.vigolium/recovered instead of deleting it, so the partial results survive the failure (requires -S)")
}

// registerEventsFlag declares --events. One definition, shared by the full scan
// commands and the lightweight ones: registering it twice with different help
// text meant `scan --help` and `scan-url --help` documented the same flag
// differently.
func registerEventsFlag(flags *pflag.FlagSet) {
	flags.StringVar(&scanOpts.Events, "events", "",
		"Emit a machine-readable event stream to stdout while the scan runs: 'ndjson' (one JSON object per line, flushed per event). "+
			"The human console stays on stderr, so a driver reads the stream with 2>/dev/null. "+
			"Events: scan.started, phase.started/progress/finished, waf.block, waf.pacing, finding.new, error, scan.finished.")
}

// markFlagDeprecated hides oldName from --help and makes pflag emit a one-time
// stderr warning ("Flag --<oldName> has been deprecated, use --<replacement>")
// when it is set. Use after registering a hidden alias whose variable is shared
// with the canonical flag. pflag's MarkDeprecated sets both Deprecated and Hidden
// (Deprecated alone still renders in usage, since FlagUsages only skips Hidden);
// the error is ignored — it only fires for an unknown flag or an empty message.
func markFlagDeprecated(flags *pflag.FlagSet, oldName, replacement string) {
	_ = flags.MarkDeprecated(oldName, "use --"+replacement)
}
