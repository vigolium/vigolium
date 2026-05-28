package cli

import (
	"time"

	"github.com/spf13/pflag"
)

func registerNativeScanFlags(flags *pflag.FlagSet, includeAuth bool) {
	// Target-Format group
	flags.BoolVar(&scanOpts.FormatUseRequiredOnly, "required-only", false, "Parse only required fields from input format (ignore optional)")
	flags.BoolVar(&scanOpts.SkipFormatValidation, "skip-format-validation", false, "Skip validation of input file format")

	// Output group
	flags.StringVarP(&scanOpts.Output, "output", "o", "", "Write findings to specified output file")
	flags.BoolVar(&scanOpts.ShowStats, "stats", false, "Show live progress stats during scanning")
	flags.BoolVar(&scanOpts.IncludeResponseInOutput, "include-response", false, "Include full HTTP response body in output")
	flags.BoolVar(&scanOpts.OmitResponse, "omit-response", false, "Omit raw HTTP request/response bytes from output file (keeps metadata, smaller files)")
	flags.StringVar(&scanReportSharedURL, "report-url", "",
		"URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")

	// Optimization group
	flags.IntVar(&scanOpts.Retries, "retries", 1, "Number of retry attempts for failed requests")
	flags.BoolVar(&scanOpts.Stream, "stream", false, "Process targets as a stream without buffering or deduplication")

	// Request group
	flags.StringSliceVarP(&scanOpts.Headers, "header", "H", nil, "Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token')")
	flags.StringToStringVarP(&scanOpts.AdvancedOptions, "advanced-options", "a", nil, "Module-specific options as key=value (e.g. -a xss.dom=true)")

	// Content discovery flags
	flags.BoolVar(&scanOpts.DiscoverEnabled, "discover", false, "Enable content discovery phase before scanning")
	flags.DurationVar(&scanOpts.DiscoverMaxDuration, "discover-max-time", 1*time.Hour, "Max time for content discovery per target")
	flags.StringVar(&scanOpts.FuzzWordlistPath, "fuzz-wordlist", "", "Custom fuzz wordlist path for discovery (enables fuzzing on the fly)")
	flags.BoolVar(&scanOpts.NoPrefixBreaker, "no-prefix-breaker", false, "Disable per-prefix circuit breaker that stops discovery from recursing into trap directories")

	// Browser-based spidering flags
	flags.BoolVar(&scanOpts.SpideringEnabled, "spider", false, "Enable browser-based spidering phase before scanning")
	flags.DurationVar(&scanOpts.SpideringMaxDuration, "spider-max-time", 30*time.Minute, "Max time for spidering per target")
	flags.StringVarP(&scanOpts.SpideringBrowserEngine, "browser-engine", "E", "chromium", "Browser engine: 'chromium', 'ungoogled', or 'fingerprint'")
	flags.IntVarP(&scanOpts.SpideringBrowserCount, "browsers", "b", 1, "Number of parallel browser instances for spidering")
	flags.BoolVar(&scanOpts.SpideringHeadless, "headless", true, "Run browser in headless mode")
	flags.BoolVar(&scanOpts.SpideringHeaded, "headed", false, "Show the browser window during spidering (sugar for --headless=false; wins when both are set)")
	flags.BoolVar(&scanOpts.SpideringNoCDP, "no-cdp", false, "Disable Chrome DevTools Protocol event listener detection")
	flags.BoolVar(&scanOpts.SpideringNoForms, "no-forms", false, "Disable automatic form detection and filling during spidering")

	// External intelligence harvesting flags
	flags.BoolVar(&scanOpts.ExternalHarvestEnabled, "external-harvest", false, "Enable external intelligence gathering phase (Wayback, CT logs, etc.)")

	// KnownIssueScan flags
	flags.StringSliceVar(&scanOpts.KnownIssueScanTags, "known-issue-scan-tags", nil, "Nuclei template tags to include (comma-separated)")
	flags.StringSliceVar(&scanOpts.KnownIssueScanExcludeTags, "known-issue-scan-exclude-tags", nil, "Nuclei template tags to exclude (comma-separated)")
	flags.StringSliceVar(&scanOpts.KnownIssueScanSeverities, "known-issue-scan-severities", nil, "Filter Nuclei templates by severity (critical,high,medium,low,info)")
	flags.StringVar(&scanOpts.KnownIssueScanTemplatesDir, "known-issue-scan-templates-dir", "", "Custom Nuclei templates directory")

	// OAST flags
	flags.StringVar(&scanOpts.OastURL, "oast-url", "", "Fixed out-of-band callback URL (overrides auto-generated interactsh URL)")

	flags.BoolVar(&scanOpts.UploadResults, "upload-results", false, "Upload scan results to cloud storage after completion (requires storage config)")

	// Stateless mode
	flags.BoolVarP(&globalStateless, "stateless", "S", false, "Use a temporary database that is discarded after the scan (pass --output/--format to persist results)")
	flags.BoolVar(&globalSplitByHost, "split-by-host", false, "In stateless multi-target mode (-S -T file), write a separate per-host output file (base-<host>.<ext>) instead of one unified file")

	if includeAuth {
		flags.StringSliceVar(&scanOpts.AuthFiles, "auth-file", nil,
			"Path to auth file (YAML/JSON, single session or sessions: bundle), "+
				"or bare name resolved against scanning_strategy.session.session_dir. Repeatable.")
		flags.StringSliceVar(&scanOpts.AuthInline, "auth", nil,
			"Inline session in 'name:Header:value' format. Repeatable.")

		// Accept the former flag names (--session / --session-file) shown in older
		// guides and copy-pasted commands as aliases for --auth / --auth-file. A
		// normalize func routes them to the same flag so both spellings share one
		// value list. Registering duplicate flags bound to the same slice would
		// instead make `--auth X --session Y` silently drop X, because pflag tracks
		// the "changed" state per flag and each flag's first Set replaces the slice.
		flags.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
			switch name {
			case "session":
				name = "auth"
			case "session-file":
				name = "auth-file"
			}
			return pflag.NormalizedName(name)
		})
	}
}
