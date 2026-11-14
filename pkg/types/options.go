package types

import (
	"maps"
	"time"

	"github.com/vigolium/vigolium/pkg/output/formats"
)

type Options struct {
	Concurrency int // Number of parallel workers

	TargetsFilePaths []string // target-list files (-T/--target-file, repeatable); lines from all are merged
	// TargetsSeededFromFile records that TargetsFilePaths was promoted into
	// Targets and then cleared. The -P fan-out only splits a -T file, so this is
	// how a later consumer still knows the run was file-driven — without it, the
	// fan-out hint would offer -P to a -t-only run, where it degrades back to a
	// single serial scan with a warning.
	TargetsSeededFromFile bool
	// TargetAdmission is the CLI's scope verdict over Targets, set when the
	// targets ARE the scan's input (not a -i spec's base URL, a raw-request
	// stdin, or a DB rescan). The CLI reads it for the banner and scan.started;
	// non-nil also tells a runner built on a custom input source to admit
	// Targets itself. The runner recomputes the verdict and owns the decision.
	TargetAdmission *TargetAdmission
	InputFileMode   string // json, jsonb, list
	// InputFileModeExplicit: -I was given, so a URL-list InputFileMode is the
	// operator's choice and the input file is not content-sniffed into another
	// format (source.FileSourceConfig.FormatExplicit).
	InputFileModeExplicit bool
	Stream                bool
	Stdin                 bool
	// --input-read-timeout used to land here and go no further: nothing in the
	// runner ever read this field, so the advertised deadline was inert and a
	// pipe that never closed hung the process. The deadline is now applied where
	// the bytes are actually read, by pkg/cli/stdin.go, and it deliberately does
	// NOT reach the streaming URL-list source: `httpx ... | vigolium scan` keeps
	// its stdin open for as long as the producer runs, and that is the point.
	// Output is the file to write found results to.
	Output string
	// IncludeResponseInOutput includes HTTP response in output file.
	IncludeResponseInOutput bool
	// OmitResponse drops raw HTTP request/response bytes from file output
	// (keeps metadata; produces much smaller files).
	OmitResponse bool

	SkipFormatValidation  bool
	FormatUseRequiredOnly bool

	// OpenAPI/Swagger options
	OpenAPIBaseURL        string
	OpenAPIUseSpecServers bool
	SpecHeaders           []string
	OpenAPIVariables      []string
	OpenAPIDefaultParam   string

	Targets        []string
	ExcludeTargets []string

	Silent bool
	// ScanConfigPrinted indicates the scan configuration summary has already been
	// printed by the caller (e.g. CLI). When true, the runner skips its own summary.
	ScanConfigPrinted bool
	// ShowStats displays scan statistics every 5 seconds
	ShowStats bool

	// MaxPerHost is the maximum concurrent requests per host
	MaxPerHost int
	// NoWafPacing disables the proactive CDN/WAF-edge pacing (pre-arming the
	// per-host limiter when an edge is fingerprinted). The reactive WAF-block back-off
	// still applies. Wired from the --no-waf-pacing CLI flag; a probe-only run
	// turns it on for itself (see runner.ApplyNativePhaseSelection).
	NoWafPacing bool
	// NoWafPacingSet records that the operator asked for the value in
	// NoWafPacing. Same reason as RecordRedirectChainSet: "off" is both the
	// default and something an operator can deliberately ask for, so a phase
	// applying its own default cannot tell them apart from the bool alone.
	NoWafPacingSet bool
	// MaxHostError is the maximum number of errors allowed for a host
	MaxHostError int
	// MaxFindingsPerModule caps findings emitted per module (0 = unlimited)
	MaxFindingsPerModule int
	// Verbose flag indicates whether to show verbose output or not
	Verbose bool
	// Debug flag enables dumping raw HTTP requests for debugging
	Debug bool
	// DumpTraffic prints every HTTP request/response to stderr in Burp-style format
	DumpTraffic bool
	// JSONOutput enables JSON output to stdout
	JSONOutput bool
	// OutputFormats selects the output formats: console, jsonl, html (comma-separated for multiple)
	OutputFormats []string
	// CIOutput enables CI-friendly output: JSONL findings only, no color, no banners
	CIOutput bool
	// DeferredJSONLExport routes jsonl output through the post-scan, project-scoped
	// envelope export ({"type":...,"data":...}) instead of the live, nuclei-style
	// ResultEvent stream. Set for `--format jsonl` outside CI mode so the scan,
	// stateless, and `export` paths all emit the same unified schema. When true,
	// StandardWriter suppresses its live jsonl file/stdout output (unless console
	// is also requested, which keeps its own live output).
	DeferredJSONLExport bool
	// CapturedConsole marks a scan whose stdout/stderr is being captured to a file
	// rather than shown on a live terminal (the per-target <output>.console.log the
	// `-P`/--parallel fan-out writes for each child). It makes the captured log a
	// useful standalone record: the live finding stream is emitted to stdout even
	// when jsonl is deferred and console isn't among --format (so findings land in
	// the file, not only in the jsonl/html exports), and the periodic "[status]"
	// progress ticker is suppressed (it's repetitive noise in a file). Set by the
	// parent on each child via the hidden --captured-console flag; never user-set.
	CapturedConsole bool
	// StdoutDocument reserves stdout for the single -j scan document, written
	// once the scan is over (pkg/cli scan_document.go). The live finding stream
	// stays off stdout, as under --events: findings are echoed to stderr
	// instead, and the document carries them.
	StdoutDocument bool
	// Events selects the machine event stream written to stdout ("ndjson", or ""
	// for none). It is orthogonal to OutputFormats: formats decide what a scan
	// LEAVES BEHIND, Events decides what it REPORTS WHILE RUNNING. The human
	// console keeps stderr either way, so a driver reads the stream off stdout
	// with `2>/dev/null` and an interactive operator sees no difference.
	Events string

	Timeout time.Duration
	Retries int

	Modules        []string
	PassiveModules []string
	// ModulePatterns and ModuleTags are the raw -m and --module-tag values.
	// Modules already holds what they resolved to among the built-in modules;
	// the runner re-applies them to the JS/YAML extensions it loads, which the
	// CLI cannot see (so `-m csp` also selects ext-csp-check).
	ModulePatterns []string
	ModuleTags     []string

	ProxyURL string

	// Database options
	ConfigPath  string
	ScanUUID    string
	ProjectUUID string

	RestrictLocalNetworkAccess bool
	// DialerTimeout sets the timeout for network requests.
	DialerTimeout time.Duration
	// DialerKeepAlive sets the keep alive duration for network requests.
	DialerKeepAlive time.Duration
	// SystemResolvers enables override of nuclei's DNS client opting to use system resolver stack.
	SystemResolvers bool
	// MaxRedirects is the maximum numbers of redirects to be followed.
	MaxRedirects int
	// TargetsSchemeAssumed holds the entries of Targets whose scheme this
	// process supplied because the line carried none, keyed by the NORMALIZED
	// target (the spelling that ends up in Targets).
	//
	// Only the probe sweep reads it, and only to decide whether it may test the
	// guess: a schemeless line means "whatever this host speaks", so the sweep
	// connects before it requests and probes https when the plaintext port is
	// closed. An explicitly-schemed target is never second-guessed. Populated
	// at both normalization seams (the CLI merge and normalizeTargetSchemes),
	// since the information is destroyed by normalization itself.
	TargetsSchemeAssumed map[string]struct{}
	// FollowRedirects enables following redirects for http request module
	FollowRedirects bool
	// FollowRedirects enables following redirects for http request module only on the same host
	FollowHostRedirects bool
	// DisableRedirects disables following redirects for http request module
	DisableRedirects bool
	// TransportProfile selects the connection-pool shape. HTTP client tuning is
	// bimodal and the two modes want opposite settings, so one profile cannot
	// serve both:
	//
	//   ""      few hosts, many requests each (the scanner's normal shape):
	//           keep-alives on, a warm idle pool sized to the per-host
	//           concurrency ceiling, a response-header timeout generous enough
	//           that a deliberately-delayed response (time-based blind SQLi
	//           sleeps ~6s) is never cut off at the transport layer.
	//   "sweep" many hosts, one request each: keep-alives off (the pool never
	//           pays off and idle sockets hold file descriptors), and a short
	//           response-header timeout, because the 3% of hosts that accept
	//           and then stall are what sets the run time.
	//
	// See http.TransportProfile*.
	TransportProfile string

	// RedirectMode selects which redirects the requester follows. It is the
	// successor to the FollowRedirects/FollowHostRedirects pair, which could not
	// express "follow within the registrable domain" — the mode a host sweep
	// wants, where www.example.com -> example.com is the same application but
	// example.com -> tracker.example.net is not. Empty means "leave the legacy
	// pair in charge"; see http.ResolveRedirectMode.
	RedirectMode string
	// RecordRedirectChain persists every followed redirect hop as its own
	// http_records row (chained by parent_uuid), instead of keeping only the
	// final response. Off by default: it multiplies row counts on every scan,
	// and only a host-sweep style run actually wants the intermediate hops.
	// A probe-only run turns it on for itself (see runner.ApplyNativePhaseSelection).
	RecordRedirectChain bool
	// RecordRedirectChainSet records that the operator asked for the value in
	// RecordRedirectChain, rather than it being the zero value. Mirrors
	// RateLimitExplicitlySet, and for the same reason: "off" is both the default
	// and a thing an operator can deliberately ask for, so a phase applying its
	// own default cannot tell them apart from the bool alone.
	RecordRedirectChainSet bool

	// SNI custom hostname
	SNI string
	// Force HTTP2 requests
	ForceAttemptHTTP2 bool

	// ScanOnReceive enables DB watcher to auto-scan ingested records
	ScanOnReceive bool
	// FullNativeScanOnReceive runs the full native scan pipeline (discovery,
	// spidering, dynamic-assessment) continuously on received records, rather
	// than the dynamic-assessment-only pipeline used by plain ScanOnReceive.
	FullNativeScanOnReceive bool
	// ScanOnReceiveIdleTimeout, when > 0, causes the continuous DB input source
	// to return io.EOF after this long without any new rows. Not exposed as a
	// CLI flag — the server daemon runs forever — but used by e2e tests to
	// force a scan-on-receive run to terminate on its own.
	ScanOnReceiveIdleTimeout time.Duration

	// ManagedScanRecord signals that an external orchestrator (the API server)
	// already created the scan record and owns its pending/queued/running
	// transitions. The runner then skips its own CreateScan so the two do not
	// compete over the same row; the runner still owns the single terminal
	// CompleteScan (recorded on a detached context so cancellation can't fail it).
	ManagedScanRecord bool

	// DisableFetchResponse skips fetching HTTP responses during ingestion
	DisableFetchResponse bool

	AdvancedOptions map[string]string

	// Headers contains custom headers to include in all HTTP requests
	Headers []string

	// ScanMaxDuration caps total wall-clock time for the whole native scan
	// (all phases combined). 0 = unbounded. Sourced from --scanning-max-duration.
	ScanMaxDuration time.Duration

	// MaxRequests caps the wire attempts the whole scan may send, and
	// MaxRequestsPerHost the attempts to any one target host (0 = unlimited).
	// Sourced from --max-requests / --max-requests-per-host, else
	// scanning_pace.max_requests / max_requests_per_host. Enforced by the egress
	// gate's request budget (pkg/core/egress.Budget).
	MaxRequests        int64
	MaxRequestsPerHost int64

	// Content discovery options
	DiscoverEnabled     bool
	DiscoverMaxDuration time.Duration
	FuzzWordlistPaths   []string // CLI --discovery-wordlist (repeatable): discovery fuzz wordlists, streamed in order and deduplicated (also enables fuzzing)
	// NoDiscoveryFuzz turns discovery's /FUZZ brute-force OFF unconditionally.
	// It outranks every reason fuzzing would otherwise switch on (--intensity
	// deep, a discovery-only run, the low-yield auto-enable), because it is the
	// operator saying "do not send thousands of guessed paths at this host" and a
	// preset quietly overruling that is the failure that matters.
	NoDiscoveryFuzz bool
	NoPrefixBreaker bool // Disable per-prefix circuit breaker (default: enabled)
	// DiscoveryExtensions (--discovery-extensions) are extensions every
	// discovered name is also tried with (ffuf's -e), swept without the
	// confirmation gate. DiscoveryMaxDepth (--discovery-max-depth) overrides
	// discovery.recursion.max_depth; 0 with the flag typed turns recursion off.
	// Both are applied to the discovery settings by the CLI.
	DiscoveryExtensions []string
	DiscoveryMaxDepth   int

	// FollowSubdomains, when set, lets the subdomain_harvest passive module pull
	// the exact in-scope subdomains it discovers in responses into the scan:
	// each discovered host is added to a dynamic scope allow-set and fed back for
	// scanning (the apex itself is NOT wildcarded). Auto-enabled at Intensity "deep".
	FollowSubdomains bool

	// PortSweepPorts overrides the alternate-port sweep's port list (CLI
	// --port-sweep-ports, comma-separated). Empty uses the configured/default
	// list. The sweep itself runs whenever FollowSubdomains or Intensity "deep".
	PortSweepPorts string

	// ProbeEnabled runs the host-sweep phase: one request per CLI target,
	// passive modules only, no content discovery and no fuzzing. It is the
	// `vigolium run probe` entry point (equivalently `scan --only probe`), meant
	// for answering "which of these thousands of hosts are alive, what are they
	// running, and which are worth a real scan".
	ProbeEnabled bool

	// TLSProbe makes the probe phase complete a TLS handshake per HTTPS target
	// and record the negotiated version/cipher and the leaf certificate as a host
	// observation (host_observations.tls), not on a record — a certificate
	// belongs to the host, not to any one request (see pkg/tlsprobe).
	TLSProbe bool

	// ProbeFavicon makes the probe phase fetch each answering origin's icon
	// once (the page's <link rel="icon">, else /favicon.ico), hash it the way
	// the fingerprint phase does (mmh3 for Shodan/FOFA, MD5, SHA-256), and
	// store it as a host observation (host_observations.favicon). --favicon.
	ProbeFavicon bool

	// FingerprintEnabled runs the fingerprint phase: per origin, a bounded set
	// of reads (well-known paths, favicon, CORS preflight, OPTIONS, vhost
	// variants, a not-found baseline) whose conclusions are stored as host facts.
	// `vigolium fingerprint` (equivalently `run fingerprint`).
	FingerprintEnabled bool
	// FingerprintDepth is light, standard or full (recon.Depth); empty picks
	// standard for a short target list and light for a long one.
	FingerprintDepth string

	// Browser-based spidering options
	SpideringEnabled       bool
	SpideringMaxDuration   time.Duration
	SpideringBrowserEngine string
	SpideringBrowserCount  int
	SpideringHeadless      bool
	SpideringHeaded        bool
	SpideringNoCDP         bool
	SpideringNoForms       bool
	// SpideringBrowserInsecure turns every spidering.browser_compat exception on
	// (--browser-insecure).
	SpideringBrowserInsecure bool
	// SpideringRequireAuth sets spidering.require_auth (--require-auth).
	SpideringRequireAuth bool

	// CarryBrowserSession carries the spidering browser's WAF/bot-cleared session
	// (cookies, and — only when a non-default User-Agent is configured — the
	// browser UA) forward into content discovery and dynamic assessment, scoped
	// to the same host. On by default whenever spidering runs; the
	// --no-carry-browser-session flag sets it false.
	CarryBrowserSession bool

	// Known Issue Scan options
	KnownIssueScanEnabled     bool
	KnownIssueScanTags        []string
	KnownIssueScanExcludeTags []string
	KnownIssueScanSeverities  []string
	// KnownIssueScanTemplatesDirs is the repeatable --known-issue-scan-templates-dir;
	// KnownIssueScanTemplates the repeatable --known-issue-scan-templates (template
	// files or IDs, nuclei's -t for a single template).
	KnownIssueScanTemplatesDirs []string
	KnownIssueScanTemplates     []string

	// Pre-scan external intelligence harvesting
	ExternalHarvestEnabled bool

	// ScopeOriginMode overrides the scope.cli_origin_mode config from the CLI --scope-origin flag.
	ScopeOriginMode string

	// ScanningStrategy selects the named scanning strategy (e.g. "lite", "balanced", "deep")
	ScanningStrategy string
	// ScanningProfile selects a scanning profile (from --scanning-profile or config)
	ScanningProfile string
	// Intensity is the resolved scan intensity preset (quick, balanced, deep) for display/logging.
	Intensity string
	// HeuristicsCheck controls the pre-scan heuristics check level: "none", "basic", "advanced".
	HeuristicsCheck string
	// SkipDynamicAssessment disables the dynamic-assessment phase when set by a strategy
	SkipDynamicAssessment bool
	// SkipIngestion disables the discovery/ingestion phase when set by --only
	SkipIngestion bool
	// OnlyPhase isolates a single scanning phase (discover, external-harvest, dynamic-assessment)
	OnlyPhase string
	// SkipPhases disables one or more phases while keeping all others enabled
	SkipPhases []string
	// PhaseSelection records what turned a phase off during scan-options
	// resolution, keyed by canonical phase id: "strategy", "only", "skip",
	// "module_selection" or "heuristics". The scan plan reads it for each
	// phase's disabled_by; a phase absent here is off by default or by a gate.
	PhaseSelection map[string]string
	// SkipPortSweep disables the alternate-port sweep even where deep /
	// --follow-subdomains would schedule it. Set by --skip port-sweep and by any
	// --only that does not list port-sweep (see runner.ApplyNativePhaseSelection).
	SkipPortSweep bool
	// SkipTargetedRespider disables the targeted re-spider step (--skip
	// targeted-respider) while keeping spidering itself.
	SkipTargetedRespider bool
	// SkipPreflight is set by --skip preflight: the runner does not send its
	// reachability GET to each admitted CLI target before the phases, so a dead
	// target is no longer reported as no_targets_reachable / targets_unreachable
	// (scope admission still applies).
	SkipPreflight bool

	// OastURL is a fixed OAST callback URL (from --oast-url flag)
	OastURL string

	// SpideringMaxDurationSource is where SpideringMaxDuration came from:
	// "flag" (typed --spider-max-time), a config.PaceSource value when the
	// scanning_pace resolution supplied it ("factor", "phase", "common"), or ""
	// (the flag default / not resolved). Only a "factor" value is subject to the
	// spidering floor (runner.SpideringBudget).
	SpideringMaxDurationSource string

	// ConcurrencyExplicitlySet tracks whether the CLI -c/--concurrency flag was explicitly provided
	ConcurrencyExplicitlySet bool
	// MaxPerHostExplicitlySet tracks whether the CLI --max-per-host flag was explicitly provided
	MaxPerHostExplicitlySet bool
	// RateLimitExplicitlySet tracks whether the CLI --rate-limit flag was
	// explicitly provided. RateLimit itself always carries a value now (the
	// documented default applies when the flag is absent), so "did the operator
	// ask for this rate" can no longer be read off the value.
	RateLimitExplicitlySet bool

	// RateLimit is the global outbound requests-per-second cap for native scanning.
	// It carries the documented 100 rps default when --rate-limit is not typed
	// (see RateLimitExplicitlySet), so the cap is on by default; 0 means unlimited.
	// When > 0 the scan's Services get a shared token-bucket rate limiter enforced
	// at the request boundary.
	RateLimit int

	// ExtensionsOnly skips all built-in Go modules; runs only JS/YAML extension modules.
	ExtensionsOnly bool

	// ClusterRequests enables request clustering to deduplicate concurrent identical HTTP requests
	ClusterRequests bool

	// ShutdownTimeout is the maximum time to wait for in-flight work during graceful shutdown (default: 30s)
	ShutdownTimeout time.Duration

	// Multi-session authentication for IDOR/BOLA testing.
	// AuthFiles are paths from --auth-file flags. Each is a YAML/JSON file
	// (single session or sessions: bundle) or a bare name resolved against
	// scanning_strategy.session.session_dir.
	AuthFiles []string
	// AuthInline are inline session values from --auth flags in "name:Header:value" format.
	AuthInline []string
	// AuthBestEffort when true treats auth init errors as warnings instead of
	// hard failures. Use for AI-generated auth configs that may be malformed —
	// the scan proceeds without sessions rather than aborting.
	AuthBestEffort bool

	// UploadResults uploads scan results to cloud storage after completion (requires storage config).
	UploadResults bool

	// Stateless uses a temporary SQLite database that is deleted after the scan completes.
	// Requires --output to be set. Incompatible with --db.
	Stateless bool

	// SplitByHost, in stateless multi-target mode (-S -T file), scans each target
	// in its own temporary database and writes a separate per-host output file
	// (base-<host>.<ext>). When false (default), all targets share one pass and
	// one unified output file. No effect outside stateless + target-file scans.
	SplitByHost bool

	// DBIsolate scans into a private temporary SQLite database and merges the
	// results into the destination --db (or the default DB) once the scan
	// finishes, then discards the temp database. Lets many parallel scan
	// processes target the same --db without contending on a single SQLite
	// writer during the scan: contention collapses to a short, serialized,
	// retrying bulk merge at the end. Requires a SQLite destination and is
	// mutually exclusive with --stateless (which discards results entirely).
	DBIsolate bool

	// Resume, in the stateless parallel fan-out (-S -T --split-by-host -P>1),
	// loads the run's progress manifest (<output>.progress.json) and skips every
	// target that already completed cleanly, scanning only the remainder. The
	// manifest is written incrementally during every such run regardless of this
	// flag; Resume only changes the read path. No effect outside that fan-out.
	Resume bool

	// Parallel is how many targets to scan at once in stateless multi-target
	// mode (-S -T file --split-by-host). Each target runs as an isolated child
	// vigolium process that keeps its own --concurrency worker pool, so the real
	// in-flight request count is roughly Parallel × Concurrency. Default 1
	// (sequential). Values > 1 require --stateless, a target file, and
	// --split-by-host; outside that combination the flag is rejected up front.
	Parallel int

	// NoTechFilter disables the tech-stack allowlist gate so every module runs
	// regardless of the host's detected stack. Set by --no-tech-filter and
	// applied automatically when Intensity == "deep".
	NoTechFilter bool

	// AllowRiskyPayloads is the --allow-risky-payloads flag: nil when the flag
	// was not passed (config dynamic-assessment.allow_risky_payloads decides),
	// otherwise the explicit CLI value, which wins over config. When the resolved
	// value is true (or Intensity == "deep"), risk:high payloads and modules run.
	// Safe is --safe: the bounded, non-mutating preset (embedded overlay
	// presets/overlays/safe.yaml, risky payloads off, GET/HEAD-only traffic).
	Safe bool

	// ConcurrencyCeiling caps every phase's worker count when > 0 and -c was
	// not typed: a strategy's pace ceiling or --safe. A scanning_pace.<phase>
	// section (a profile's dynamic-assessment concurrency: 100) used to win
	// over the narrowed global value.
	ConcurrencyCeiling int

	AllowRiskyPayloads *bool

	// NoParamDedup is --no-param-dedup: turn off the cross-module (param,
	// vuln-class) skip so every module of a class tests a parameter even after
	// another one reported it. For audit runs that want every technique's hit.
	NoParamDedup bool

	// ParamMining is --param-mining: nil when the flag was not passed (the
	// phase then follows the intensity: on at deep, off below it), otherwise
	// the explicit value, which wins in both directions.
	ParamMining *bool
}

// DefaultConcurrency is the built-in scan worker count, used wherever nobody
// configured one: the -c flag's default, the scanning_pace common default, the
// REST API's per-scan default, and DefaultOptions below.
//
// It lives here because pkg/types imports nothing else in this module, so
// every layer that needs it can reach it. Four packages used to spell this
// number themselves and had drifted to 50/40/50/50 — the CLI and the REST API
// ran the same scan at different speeds, and `docs/getting-started.md` had to
// document the discrepancy ("generated config default 40; raw CLI fallback
// 50"). The shipped public/vigolium-configs.example.yaml carries a copy too,
// since it is written verbatim as the user's config on first run.
const DefaultConcurrency = 25

// DefaultOptions returns default options for the scanner
func DefaultOptions() *Options {
	return &Options{
		Concurrency:          DefaultConcurrency,
		MaxPerHost:           DefaultMaxPerHost,
		Timeout:              15 * time.Second,
		Retries:              1,
		MaxHostError:         30,
		MaxFindingsPerModule: 50,
		PassiveModules:       []string{"all"},
		ClusterRequests:      true,
		ShutdownTimeout:      30 * time.Second,
		Parallel:             1,
		CarryBrowserSession:  true,
	}
}
func (options *Options) ShouldUseHostError() bool {
	return options.MaxHostError > 0
}

// ShouldFollowHTTPRedirects determines if http redirects should be followed
func (options *Options) ShouldFollowHTTPRedirects() bool {
	return options.FollowRedirects || options.FollowHostRedirects
}

// HasFormat returns true if the given format is in the OutputFormats list.
func (options *Options) HasFormat(format string) bool {
	for _, f := range options.OutputFormats {
		if f == format {
			return true
		}
	}
	return false
}

// OutputBasePath returns the base path for output files by stripping any
// known format extension (.jsonl, .html, .json) from the Output path.
func (options *Options) OutputBasePath() string {
	return StripFormatExtension(options.Output)
}

// OutputPathForFormat returns the output file path for a specific format,
// using the base path with the appropriate extension appended.
func (options *Options) OutputPathForFormat(format string) string {
	return FormatOutputPath(options.OutputBasePath(), format)
}

// StripFormatExtension removes a known format extension (.jsonl, .html, .json,
// .md, .tar.gz, …) from a path, returning the base suitable for appending a new
// extension. The extension set comes from the output format table
// (pkg/output/formats); only the last extension is stripped.
func StripFormatExtension(path string) string {
	return formats.StripExtension(path)
}

// FormatOutputPath appends the given format's file extension (aliases
// accepted) to basePath. The format→extension mapping is the output format
// table's (pkg/output/formats), shared by the scan commands, `vigolium export`
// and the REST server. fs and console have no extension: fs names a directory
// base (<base>-traffic/, <base>-findings/) and console's transcript is the base.
func FormatOutputPath(basePath, format string) string {
	return formats.OutputPath(basePath, format)
}

// MarkSchemeAssumed merges assumed into TargetsSchemeAssumed, creating the map
// on first use.
//
// A method on Options because the two places that normalize a target list live
// in different packages — the CLI merge and the runner's normalizeTargetSchemes
// — and each otherwise carries its own copy of the same lazy-init.
func (o *Options) MarkSchemeAssumed(assumed map[string]struct{}) {
	if o == nil || len(assumed) == 0 {
		return
	}
	if o.TargetsSchemeAssumed == nil {
		o.TargetsSchemeAssumed = make(map[string]struct{}, len(assumed))
	}
	maps.Copy(o.TargetsSchemeAssumed, assumed)
}

// NotePhaseDisabled records why phase was turned off (Options.PhaseSelection).
// A --skip never relabels a phase the module selection already skipped: the
// module selection is what added it to the skip list.
func (o *Options) NotePhaseDisabled(phase, by string) {
	if o.PhaseSelection == nil {
		o.PhaseSelection = map[string]string{}
	}
	if by == "skip" && o.PhaseSelection[phase] == "module_selection" {
		return
	}
	o.PhaseSelection[phase] = by
}

// NotePhaseEnabled clears a recorded reason once a later step turns the phase
// back on (--only naming a phase the strategy turned off).
func (o *Options) NotePhaseEnabled(phase string) {
	delete(o.PhaseSelection, phase)
}
