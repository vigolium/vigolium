package types

import (
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	Concurrency int // Number of parallel workers

	TargetsFilePaths []string // target-list files (-T/--target-file, repeatable); lines from all are merged
	InputFileMode    string   // json, jsonb, list
	Stream          bool
	Stdin           bool
	// Time to wait between each input read operation before closing the stream

	InputReadTimeout time.Duration
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

	Timeout time.Duration
	Retries int

	Modules        []string
	PassiveModules []string

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
	// FollowRedirects enables following redirects for http request module
	FollowRedirects bool
	// FollowRedirects enables following redirects for http request module only on the same host
	FollowHostRedirects bool
	// DisableRedirects disables following redirects for http request module
	DisableRedirects bool

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

	// DisableFetchResponse skips fetching HTTP responses during ingestion
	DisableFetchResponse bool

	AdvancedOptions map[string]string

	// Headers contains custom headers to include in all HTTP requests
	Headers []string

	// ScanMaxDuration caps total wall-clock time for the whole native scan
	// (all phases combined). 0 = unbounded. Sourced from --scanning-max-duration.
	ScanMaxDuration time.Duration

	// Content discovery options
	DiscoverEnabled     bool
	DiscoverMaxDuration time.Duration
	FuzzWordlistPath    string // CLI override for discovery fuzz wordlist (also enables fuzzing)
	NoPrefixBreaker     bool   // Disable per-prefix circuit breaker (default: enabled)

	// FollowSubdomains, when set, lets the subdomain_harvest passive module pull
	// the exact in-scope subdomains it discovers in responses into the scan:
	// each discovered host is added to a dynamic scope allow-set and fed back for
	// scanning (the apex itself is NOT wildcarded). Auto-enabled at Intensity "deep".
	FollowSubdomains bool

	// PortSweepPorts overrides the alternate-port sweep's port list (CLI
	// --port-sweep-ports, comma-separated). Empty uses the configured/default
	// list. The sweep itself runs whenever FollowSubdomains or Intensity "deep".
	PortSweepPorts string

	// Browser-based spidering options
	SpideringEnabled       bool
	SpideringMaxDuration   time.Duration
	SpideringBrowserEngine string
	SpideringBrowserCount  int
	SpideringHeadless      bool
	SpideringHeaded        bool
	SpideringNoCDP         bool
	SpideringNoForms       bool

	// Known Issue Scan options
	KnownIssueScanEnabled      bool
	KnownIssueScanTags         []string
	KnownIssueScanExcludeTags  []string
	KnownIssueScanSeverities   []string
	KnownIssueScanTemplatesDir string

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

	// OastURL is a fixed OAST callback URL (from --oast-url flag)
	OastURL string

	// ConcurrencyExplicitlySet tracks whether the CLI -c/--concurrency flag was explicitly provided
	ConcurrencyExplicitlySet bool
	// MaxPerHostExplicitlySet tracks whether the CLI --max-per-host flag was explicitly provided
	MaxPerHostExplicitlySet bool

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
}

// DefaultOptions returns default options for the scanner
func DefaultOptions() *Options {
	return &Options{
		Concurrency:          50,
		MaxPerHost:           50,
		Timeout:              15 * time.Second,
		Retries:              1,
		MaxHostError:         30,
		MaxFindingsPerModule: 10,
		PassiveModules:       []string{"all"},
		ClusterRequests:      true,
		ShutdownTimeout:      30 * time.Second,
		Parallel:             1,
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

// StripFormatExtension removes known format extensions (.jsonl, .html, .json)
// from a path, returning the base suitable for appending a new extension.
func StripFormatExtension(path string) string {
	if path == "" {
		return ""
	}
	ext := filepath.Ext(path)
	switch strings.ToLower(ext) {
	case ".jsonl", ".html", ".json", ".pdf", ".sqlite", ".sqlite3", ".db":
		return strings.TrimSuffix(path, ext)
	default:
		return path
	}
}

// FormatOutputPath appends the appropriate file extension for the given format.
func FormatOutputPath(basePath, format string) string {
	if basePath == "" {
		return ""
	}
	switch format {
	case "jsonl":
		return basePath + ".jsonl"
	case "html":
		return basePath + ".html"
	case "report":
		return basePath + ".report.html"
	case "pdf":
		return basePath + ".pdf"
	case "sqlite":
		return basePath + ".sqlite"
	default:
		return basePath
	}
}
