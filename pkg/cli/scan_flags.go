package cli

import (
	"time"

	"github.com/spf13/pflag"
)

// scanNoCarryBrowserSession backs the --no-carry-browser-session flag. Carrying
// the spidering browser's cleared session forward is on by default
// (Options.CarryBrowserSession), so this negative flag inverts it into the
// option during scan setup.
var scanNoCarryBrowserSession bool

// nativeScanFlagAliases are the alternative spellings for flags registered by
// registerNativeScanFlags, keyed alias -> canonical. Shared by every command
// that registers those flags (scan, run) rather than copied per command: the two
// had already been maintained as identical literals, which is a pair that can
// drift into an alias working on one command and being an unknown flag on the
// other. Registered with addFlagAliases, so an alias and its canonical name
// drive ONE flag value and neither can silently overwrite the other.
var nativeScanFlagAliases = map[string]string{
	// Deprecated spelling kept working for one minor version. See the
	// --discovery-wordlist comment in registerNativeScanFlags.
	"fuzz-wordlist": "discovery-wordlist",
	"templates-dir": "known-issue-scan-templates-dir",
	// Short form of --no-discovery-fuzz. "Fuzzing" means two different things in
	// this CLI (the discovery phase's path brute-force, and `vigolium fuzz`), so
	// the canonical name is qualified; on a scan command there is only one
	// fuzzing to turn off, which is what makes the short alias unambiguous here.
	"no-fuzz": "no-discovery-fuzz",
	// Short form of --omit-response. The canonical name says what it does to the
	// output; "no response" is what operators reach for, and on a host sweep
	// (where the body is the bulk of every row) it is the flag most often typed.
	"no-response": "omit-response",
	// --session / --session-file: see authFlagAliases. Listed here too because
	// addFlagAliases installs the command's normalize func, replacing the one
	// registerAuthFlags set on the flag set — which left both spellings an
	// unknown flag on scan and run.
	"session":      "auth",
	"session-file": "auth-file",
}

// authFlagAliases are the former names of --auth / --auth-file, shown in older
// guides and copy-pasted commands.
var authFlagAliases = map[string]string{
	"session":      "auth",
	"session-file": "auth-file",
}

func registerNativeScanFlags(flags *pflag.FlagSet, includeAuth bool) {
	// Target-Format group
	flags.BoolVar(&scanOpts.FormatUseRequiredOnly, "required-only", false, "Parse only required fields from input format (ignore optional)")
	flags.BoolVar(&scanOpts.SkipFormatValidation, "skip-format-validation", false, "Skip validation of input file format")

	// Output group
	flags.StringVarP(&scanOpts.Output, "output", "o", "", "Write findings to specified output file")
	flags.StringVar(&scanFailOn, "fail-on", "", failOnUsage("for CI/agent gating. Scoped to this scan; implies --fail-on-partial; --soft-fail overrides; with -P it is evaluated per child."))
	flags.BoolVar(&scanFailOnPartial, "fail-on-partial", false, "Exit 5 (incomplete) when the scan's coverage was partial (a phase cut short, blocked, or failed); implied by --fail-on")
	registerBaselineFlags(flags)
	flags.BoolVar(&scanOpts.ShowStats, "stats", false, "Show live progress stats during scanning")
	flags.BoolVar(&scanPrintFinding, "print-finding", false, "After the scan, print each finding to stdout as Markdown (description + matched evidence + request/response), like 'vigolium finding --markdown'. Pairs well with -S and --silent for a quick scan.")
	flags.BoolVar(&scanPrintTrafficTree, "print-traffic-tree", false, "After the scan, print the run's HTTP traffic to stdout as a host/path hierarchy tree, like 'vigolium traffic --tree'. Pairs well with -S and --silent.")
	flags.BoolVar(&scanPrintTraffic, "print-traffic", false, "After the scan, print the run's raw HTTP request/response pairs to stdout, like 'vigolium traffic --raw'. Pairs well with -S and --silent.")
	flags.BoolVar(&scanOpts.IncludeResponseInOutput, "include-response", false, "Include full HTTP response body in output")
	flags.BoolVar(&scanOpts.OmitResponse, "omit-response", false, "Omit raw HTTP request/response bytes from output file (keeps metadata, smaller files)")
	flags.StringSliceVar(&scanExportOnly, "export-only", nil,
		"Limit the --format jsonl envelope to these record types (comma-separated: http, findings, scans, modules, oast, source-repos, scopes). Defaults to 'http' on a probe-only run, where every finding is a tech detection already carried on the record's technology field.")
	flags.StringVar(&scanReportSharedURL, "report-url", "",
		"URL for the \"Raw Report URL\" button in HTML reports (overrides VIGOLIUM_REPORT_SHARED_URL)")
	registerReportFlags(flags)
	registerEventsFlag(flags)

	// Optimization group
	flags.IntVar(&scanOpts.Retries, "retries", 1, "Number of retry attempts for failed requests")
	flags.BoolVar(&scanOpts.Stream, "stream", false, "Process targets as a stream without buffering or deduplication")

	// Request group
	flags.StringArrayVarP(&scanOpts.Headers, "header", "H", nil, "Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token'). Commas are literal — repeat -H for multiple headers.")
	flags.StringToStringVarP(&scanOpts.AdvancedOptions, "advanced-options", "a", nil, "Module-specific options as key=value (e.g. -a xss.dom=true)")

	// Content discovery flags
	flags.BoolVar(&scanOpts.DiscoverEnabled, "discover", false, "Force the content discovery phase on (balanced and deep already run it; --skip discovery turns it off)")
	flags.DurationVar(&scanOpts.DiscoverMaxDuration, "discover-max-time", 1*time.Hour, "Max time for content discovery per target")
	// --discovery-wordlist seeds the DISCOVERY phase. It was called
	// --fuzz-wordlist, which collided in name with `vigolium fuzz -w` — a
	// different knob on a different command, taking builtin list names as well as
	// paths, and not interchangeable with this one. The names promised a
	// relationship that does not exist, so the scan-phase knob is renamed and the
	// old spelling kept as a deprecated alias (registered via addFlagAliases, so
	// both spellings drive ONE flag and neither can silently overwrite the other).
	//
	// It is a StringArray (repeatable, no comma splitting) so a path containing
	// a comma stays one path; normalizeDiscoveryWordlists still splits a
	// comma-joined value when every part is an existing file.
	flags.StringArrayVar(&scanOpts.FuzzWordlistPaths, "discovery-wordlist", nil, "Custom wordlist file seeding the discovery phase's /FUZZ brute-force (enables fuzzing on the fly). Repeatable: the files are streamed in order and each word is tried once. A missing file is a usage error. Formerly --fuzz-wordlist; distinct from 'vigolium fuzz -w'.")
	flags.BoolVar(&scanOpts.NoDiscoveryFuzz, "no-discovery-fuzz", false, "Disable discovery's /FUZZ brute-force (alias --no-fuzz). Overrides every reason it would auto-enable — --intensity deep, a discovery-only run such as 'vigolium run discover', and the low-yield auto-enable. Link extraction, JS parsing, response-word harvesting and the short dir/file wordlists still run.")
	flags.BoolVar(&scanOpts.NoPrefixBreaker, "no-prefix-breaker", false, "Disable per-prefix circuit breaker that stops discovery from recursing into trap directories")
	flags.StringSliceVar(&scanOpts.DiscoveryExtensions, "discovery-extensions", nil, "Extensions discovery also tries on every wordlist name, e.g. php,bak (ffuf's -e; leading dots optional). Swept directly, without the confirm-before-fuzzing gate that otherwise guards server-side extensions. Overrides discovery.extensions.custom_list")
	flags.IntVar(&scanOpts.DiscoveryMaxDepth, "discovery-max-depth", 0, "Maximum directory recursion depth for discovery (ffuf's -recursion-depth); 0 turns recursion off. Overrides discovery.recursion.max_depth (default 5)")
	flags.BoolVar(&scanOpts.FollowSubdomains, "follow-subdomains", false, "Pull in-scope subdomains discovered in responses into the scan (exact hosts only, not the whole apex; auto-on at --intensity deep)")
	flags.StringVar(&scanOpts.PortSweepPorts, "port-sweep-ports", "", "Override the alternate HTTP(S) ports swept on CLI target hosts (comma-separated; sweep runs at --intensity deep or --follow-subdomains)")

	// Host-sweep (probe) flags
	flags.BoolVar(&scanOpts.ProbeEnabled, "probe", false, "Enable the host-sweep phase: one request per target, passive tech fingerprinting + surface scoring, no content discovery or fuzzing (same as 'vigolium run probe')")
	flags.StringVar(&scanOpts.RedirectMode, "redirect-mode", "", "Which redirects to follow: off | same-host | same-apex | in-scope | any (default in-scope; 'run probe' defaults to same-apex). 'in-scope' follows a hop only to a host the scan scope admits (same-apex when no scope is set). 'same-apex' follows within the registrable domain, so www.example.com -> example.com follows but example.com -> tracker.example.net does not. A hop to another host never carries session or -H headers. Every mode also stops at a login/SSO wall, whatever its host, and records the 3xx instead.")
	flags.BoolVar(&scanOpts.TLSProbe, "tls-probe", false, "Probe each HTTPS target's TLS: negotiated version/cipher plus the leaf certificate (subject, SANs, issuer, validity, fingerprints). Stored per host:port; read it with 'vigolium hosts -j' or as 'tls' on 'traffic -j' rows. Read by the probe phase (the fingerprint phase always probes HTTPS)")
	flags.BoolVar(&scanOpts.ProbeFavicon, "favicon", false, "Fetch each answering origin's icon once (the page's <link rel=\"icon\">, else /favicon.ico; redirects not followed) and hash it: mmh3 (Shodan http.favicon.hash, FOFA icon_hash), MD5, SHA-256. Stored per host:port; read it as 'favicon_mmh3' with 'vigolium hosts', or as 'favicon' on 'traffic -j' rows and jsonl http_record lines. Read by the probe phase (the fingerprint phase always fetches the icon)")
	flags.BoolVar(&scanOpts.RecordRedirectChain, "record-redirect-chain", false, "Store a followed redirect's hops as their own http_records rows, chained by parent_uuid, instead of keeping only the final response. Canonical hops (scheme upgrade, trailing slash, www.) collapse into their destination row, and a chain stores at most 4 rows, keeping the first and the last. Read by the probe phase; on by default under 'run probe'.")

	// Browser-based spidering flags
	flags.BoolVar(&scanOpts.SpideringEnabled, "spider", false, "Force the browser spidering phase on (balanced and deep already run it; --skip spidering turns it off)")
	flags.DurationVar(&scanOpts.SpideringMaxDuration, "spider-max-time", 30*time.Minute, "Max time for spidering per target")
	flags.StringVarP(&scanOpts.SpideringBrowserEngine, "browser-engine", "E", "chromium", "Browser engine: 'chromium', 'ungoogled', or 'fingerprint'")
	flags.IntVarP(&scanOpts.SpideringBrowserCount, "browsers", "b", 1, "Browser instances to launch for spidering (clamped to 1; for parallel crawling set spidering.tabs in the config, which runs N tabs of the one browser)")
	flags.BoolVar(&scanOpts.SpideringHeadless, "headless", true, "Run browser in headless mode")
	flags.BoolVar(&scanOpts.SpideringHeaded, "headed", false, "Show the browser window during spidering (sugar for --headless=false; wins when both are set)")
	flags.BoolVar(&scanOpts.SpideringNoCDP, "no-cdp", false, "Disable Chrome DevTools Protocol event listener detection")
	flags.BoolVar(&scanOpts.SpideringNoForms, "no-forms", false, "Disable form filling and submission during spidering (sets spidering.interaction edit_fields and submit_forms off; an explicit interaction key wins)")
	flags.BoolVar(&scanOpts.SpideringRequireAuth, "require-auth", false, "Fail a target's spidering instead of crawling anonymously when configured authentication (session cookies/auth headers) cannot be applied to the browser (sets spidering.require_auth)")
	flags.BoolVar(&scanOpts.SpideringBrowserInsecure, "browser-insecure", false, "Spider with every browser security exception on: no sandbox, TLS errors ignored, mixed content allowed, same-origin policy off. For local test apps only")
	flags.BoolVar(&scanNoCarryBrowserSession, "no-carry-browser-session", false, "Do not carry the spidering browser's cleared session (cookies + UA) into discovery/scanning (on by default when --spider runs; scoped to the same host, respects -H)")

	// External intelligence harvesting flags
	flags.BoolVar(&scanOpts.ExternalHarvestEnabled, "external-harvest", false, "Enable external intelligence gathering phase (Wayback, CT logs, etc.)")

	// KnownIssueScan flags
	flags.StringSliceVar(&scanOpts.KnownIssueScanTags, "known-issue-scan-tags", nil, "Nuclei template tags to include (comma-separated)")
	flags.StringSliceVar(&scanOpts.KnownIssueScanExcludeTags, "known-issue-scan-exclude-tags", nil, "Nuclei template tags to exclude (comma-separated)")
	flags.StringSliceVar(&scanOpts.KnownIssueScanSeverities, "known-issue-scan-severities", nil, "Filter Nuclei templates by severity (critical,high,medium,low,info)")
	// Pinning this per-run is the way to avoid the first-run clone into the shared
	// ~/nuclei-templates (see ensureTemplates). --templates-dir is the short
	// spelling, registered as an alias rather than a second flag so both drive one
	// value.
	flags.StringArrayVar(&scanOpts.KnownIssueScanTemplatesDirs, "known-issue-scan-templates-dir", nil, "Custom Nuclei templates directory (alias: --templates-dir). Pin it to avoid the one-time clone into ~/nuclei-templates. Repeatable: the first replaces known_issue_scan.templates_dir, and every named directory is loaded.")
	flags.StringArrayVar(&scanOpts.KnownIssueScanTemplates, "known-issue-scan-templates", nil, "Run only these Nuclei templates (nuclei's -t for a file): a template file, or a path relative to the templates directory such as http/cves/2021/CVE-2021-44228.yaml. Repeatable; combined with --known-issue-scan-templates-dir, the named directories run too.")

	// OAST flags
	registerOASTURLFlag(flags)

	flags.BoolVar(&scanOpts.UploadResults, "upload-results", false, "Upload scan results to cloud storage after completion (requires storage config)")

	// Stateless mode
	flags.BoolVarP(&globalStateless, "stateless", "S", false, "Use a temporary database that is discarded after the scan (pass --output/--format to persist results)")
	registerKeepDBOnErrorFlag(flags)
	flags.BoolVar(&globalSplitByHost, "split-by-host", false, "In stateless multi-target mode (-S -T file), write a separate per-host output file (base-<host>.<ext>) instead of one unified file")
	flags.BoolVar(&globalDBIsolate, "db-isolate", false, "Scan into a private temporary database, then merge results into --db (or the default DB) at the end — lets many parallel scans share one --db without write contention (SQLite only; ignored under --stateless, which keeps nothing to merge; combine with -P -T to fan out targets and export one unified output from the merged DB)")
	flags.IntVarP(&globalParallel, "parallel", "P", 1, "Scan up to N targets concurrently as isolated child processes (requires -S -T --split-by-host, OR --db-isolate -T which merges into --db and exports one unified output; each target keeps its own --concurrency, so real in-flight requests ≈ N × --concurrency)")
	flags.BoolVar(&globalResume, "resume", false, "Resume a prior -S -T --split-by-host -P run from its progress manifest (<output>.progress.json): skip targets that already completed cleanly and scan only the remainder. Run bare ('vigolium scan --resume', no other flags) to auto-discover the *.progress.json in the current directory and relaunch the saved run from it (pass -o <prefix> to disambiguate when several exist)")

	// Internal: set by the -P/--parallel parent on each child so the per-target
	// <output>.console.log captures the live finding stream (even with deferred
	// jsonl and no console format) and drops the noisy "[status]" ticker. Hidden —
	// not part of the operator-facing surface.
	flags.BoolVar(&scanOpts.CapturedConsole, "captured-console", false, "Internal: emit the live finding stream to stdout and suppress the [status] ticker (used when console output is captured to a file)")
	_ = flags.MarkHidden("captured-console")

	if includeAuth {
		registerAuthFlags(flags)
	}
}

// registerAuthFlags declares --auth / --auth-file (with the --session /
// --session-file spellings normalized onto them). One definition for scan,
// run, scan-url and scan-request.
func registerAuthFlags(flags *pflag.FlagSet) {
	flags.StringArrayVar(&scanOpts.AuthFiles, "auth-file", nil,
		"Path to auth file (YAML/JSON, single session or sessions: bundle), "+
			"or bare name resolved against scanning_strategy.session.session_dir. Repeatable; commas are literal.")
	flags.StringArrayVar(&scanOpts.AuthInline, "auth", nil,
		"Inline session in 'name:Header:value' format. Repeatable; commas are literal (header values may contain commas).")

	// Accept the former flag names (--session / --session-file) shown in older
	// guides and copy-pasted commands as aliases for --auth / --auth-file. A
	// normalize func routes them to the same flag so both spellings share one
	// value list. Registering duplicate flags bound to the same slice would
	// instead make `--auth X --session Y` silently drop X, because pflag tracks
	// the "changed" state per flag and each flag's first Set replaces the slice.
	//
	// A command that also calls addFlagAliases replaces this func with its own,
	// so its alias table must carry these entries (nativeScanFlagAliases does).
	flags.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if canonical, ok := authFlagAliases[name]; ok {
			name = canonical
		}
		return pflag.NormalizedName(name)
	})
}
