package cli

import (
	"time"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run <phase>",
	Short: "Run a single scan phase (alias for scan --only <phase>)",
	Long: `Run a single scan phase directly. Equivalent to "vigolium scan --only <phase>".

Valid phases: ingestion, discovery (deparos), external-harvest, spa, spidering (spitolas), sast, audit, extension (ext)`,
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"r"},
	RunE: func(cmd *cobra.Command, args []string) error {
		globalOnly = args[0]
		return runScanCmd(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	flags := runCmd.Flags()

	// Target-Format group
	flags.BoolVar(&scanOpts.FormatUseRequiredOnly, "required-only", false, "Use only required fields when parsing input format")
	flags.BoolVar(&scanOpts.SkipFormatValidation, "skip-format-validation", false, "Skip validation of input file format")

	// Output group
	flags.StringVarP(&scanOpts.Output, "output", "o", "", "Write findings to specified output file")
	flags.BoolVar(&scanOpts.ShowStats, "stats", false, "Display live scan statistics during execution")
	flags.BoolVar(&scanOpts.IncludeResponseInOutput, "include-response", false, "Include full HTTP response body in output")

	// Optimizations group
	flags.IntVar(&scanOpts.Retries, "retries", 1, "Number of retry attempts for failed requests")
	flags.BoolVar(&scanOpts.Stream, "stream", false, "Process input targets in stream mode without sorting")

	// Request group
	flags.StringSliceVarP(&scanOpts.Headers, "header", "H", nil, "Custom HTTP header to include (can be specified multiple times)")
	flags.StringToStringVarP(&scanOpts.AdvancedOptions, "advanced-options", "a", nil, "Advanced scan options as key=value pairs")

	// Content discovery flags
	flags.BoolVar(&scanOpts.DiscoverEnabled, "discover", false, "Run deparos content discovery before scanning")
	flags.DurationVar(&scanOpts.DiscoverMaxDuration, "discover-max-time", 1*time.Hour, "Max time for content discovery per target")

	// Browser-based spidering flags
	flags.BoolVar(&scanOpts.SpideringEnabled, "spider", false, "Run browser-based spidering before scanning")
	flags.DurationVar(&scanOpts.SpideringMaxDuration, "spider-max-time", 30*time.Minute, "Max time for spidering per target")
	flags.StringVarP(&scanOpts.SpideringBrowserEngine, "browser-engine", "E", "chromium", "Browser engine: 'chromium', 'ungoogled', or 'fingerprint'")
	flags.IntVarP(&scanOpts.SpideringBrowserCount, "browsers", "b", 1, "Number of browser instances")
	flags.BoolVar(&scanOpts.SpideringHeadless, "headless", true, "Run browser in headless mode")
	flags.BoolVar(&scanOpts.SpideringNoCDP, "no-cdp", false, "Disable CDP event listener detection")
	flags.BoolVar(&scanOpts.SpideringNoForms, "no-forms", false, "Disable automatic form filling")

	// External intelligence harvesting flags
	flags.BoolVar(&scanOpts.ExternalHarvestEnabled, "external-harvest", false, "Run pre-scan external intelligence harvesting from external sources")

	// SPA (Security Posture Assessment) flags
	flags.StringSliceVar(&scanOpts.SPATags, "spa-tags", nil, "Nuclei template tags to include (comma-separated)")
	flags.StringSliceVar(&scanOpts.SPAExcludeTags, "spa-exclude-tags", nil, "Nuclei template tags to exclude (comma-separated)")
	flags.StringSliceVar(&scanOpts.SPASeverities, "spa-severities", nil, "Filter Nuclei templates by severity (critical,high,medium,low,info)")
	flags.StringVar(&scanOpts.SPATemplatesDir, "spa-templates-dir", "", "Custom Nuclei templates directory")

	// SAST flags
	flags.StringVar(&scanOpts.SASTRuleFilter, "rule", "", "Filter SAST rules by fuzzy name match (e.g. 'gin', 'route')")
	flags.StringVar(&scanOpts.SASTAdhoc, "sast-adhoc", "", "Local path or git URL for ad-hoc SAST scan (auto-detected, results not saved to database)")

	// OAST flags
	flags.StringVar(&scanOpts.OastURL, "oast-url", "", "Fixed OAST callback URL (overrides config oast_url; disables interactsh auto-generation)")
}
