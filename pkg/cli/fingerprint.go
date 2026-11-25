package cli

import (
	"github.com/spf13/cobra"
)

// `vigolium fingerprint` is the fingerprint phase's front door, the way `run`
// is every phase's: `scan --only fingerprint` with a depth flag and a document
// whose items are the origins it fingerprinted (the `vigolium hosts` view)
// rather than findings.

// fingerprintPhase is the one phase `fingerprint` runs, whatever --only,
// --skip or --strategy the line passes (`schema commands -j` translates_to).
const fingerprintPhase = "fingerprint"

var fingerprintCmd = &cobra.Command{
	Use:   "fingerprint [url ...]",
	Short: "Fingerprint origins with a bounded set of reads and store the result as host facts",
	Long: `Fingerprint each origin — the base page (title, server, stack, security headers,
JS framework, login forms), its favicon (mmh3 for Shodan/FOFA, MD5 for Censys),
well-known paths, API-definition paths, GraphQL introspection, a CORS preflight,
OPTIONS, Host-header variants, and three random paths for the not-found baseline —
and store it per host:port. Read it later with 'vigolium hosts'.

Every request goes through the scan engine: scope, --rate-limit, --max-per-host,
--max-requests and WAF pacing apply, and each request is stored as an http_record
(source fingerprint). Redirects are not followed. Only reads are sent (GET, OPTIONS,
and one GraphQL introspection POST); no state-changing method.

--depth light (about nine reads per origin), standard (about sixty) or full (adds
sensitive paths, OPTIONS on every path that answered, and source maps). The default
is standard for up to 50 targets and light beyond that.

Equivalent to 'vigolium run fingerprint' ('--fingerprint-depth' there); either
way the -j document's items are the fingerprinted origins.`,
	Example: "  vigolium fingerprint https://app.example -j\n" +
		"  vigolium fingerprint -T hosts.txt --depth light -j --compact\n" +
		"  vigolium fingerprint -t https://app.example --depth full",
	RunE: func(cmd *cobra.Command, args []string) error {
		globalOnly = fingerprintPhase
		return runScanCmd(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(fingerprintCmd)
	flags := fingerprintCmd.Flags()
	flags.StringVar(&scanOpts.FingerprintDepth, "depth", "", "Reads per origin: light, standard or full (default standard, light past 50 targets)")
	registerInputSourceFlags(flags)
	registerHTTPClientFlags(flags)
	registerScanModuleFlags(flags)
	registerScanPipelineFlags(flags)
	registerNativeScanFlags(flags, true)
	addFlagAliases(fingerprintCmd, nativeScanFlagAliases)
}
