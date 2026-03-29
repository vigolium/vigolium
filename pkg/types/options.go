package types

import (
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	Concurrency int // Number of parallel workers

	TargetsFilePath string
	InputFileMode   string // json, jsonb, list
	Stream          bool
	Stdin           bool
	// Time to wait between each input read operation before closing the stream

	InputReadTimeout time.Duration
	// Output is the file to write found results to.
	Output string
	// IncludeResponseInOutput includes HTTP response in output file.
	IncludeResponseInOutput bool

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

	Timeout time.Duration
	Retries int

	Modules        []string
	PassiveModules []string

	ProxyURL string

	// Database options
	ConfigPath string
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

	// DisableFetchResponse skips fetching HTTP responses during ingestion
	DisableFetchResponse bool

	AdvancedOptions map[string]string

	// Headers contains custom headers to include in all HTTP requests
	Headers []string

	// Content discovery options
	DiscoverEnabled     bool
	DiscoverMaxDuration time.Duration

	// Browser-based spidering options
	SpideringEnabled       bool
	SpideringMaxDuration   time.Duration
	SpideringBrowserEngine string
	SpideringBrowserCount  int
	SpideringHeadless      bool
	SpideringNoCDP         bool
	SpideringNoForms       bool
	SpideringPilotMode     bool

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

	// ScanningStrategy selects the named scanning strategy (e.g. "lite", "balanced", "deep", "whitebox")
	ScanningStrategy string
	// ScanningProfile selects a scanning profile (from --scanning-profile or config)
	ScanningProfile string
	// HeuristicsCheck controls the pre-scan heuristics check level: "none", "basic", "advanced".
	HeuristicsCheck string
	// SkipAudit disables the audit phase when set by a strategy
	SkipAudit bool
	// SkipIngestion disables the discovery/ingestion phase when set by --only
	SkipIngestion bool
	// OnlyPhase isolates a single scanning phase (discover, external-harvest, audit, sast)
	OnlyPhase string
	// SkipPhases disables one or more phases while keeping all others enabled
	SkipPhases []string

	// SASTEnabled enables the SAST analysis phase (formerly source-aware)
	SASTEnabled bool
	// SASTRuleFilter is a fuzzy pattern for filtering SAST rules by name (from --rule flag)
	SASTRuleFilter string
	// SASTAdhoc is a local path or git URL for ad-hoc SAST scan (results not saved to DB, from --sast-adhoc flag).
	// Auto-detected: URLs (http://, https://, git@) are cloned; everything else is treated as a local path.
	SASTAdhoc string
	// SourcePath is the path to application source code (from --source flag)
	SourcePath string
	// SourceURL is a git URL to clone for source-aware scanning (from --source-url flag)
	SourceURL string

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

	// Multi-session authentication for IDOR/BOLA testing
	// Sessions are inline "name:Header:value" strings from --session flags
	Sessions []string
	// AuthConfigPath is the path to an auth-config YAML file with session definitions
	AuthConfigPath string
	// AuthConfigBestEffort when true treats auth config/session init errors as
	// warnings instead of hard failures. Use for AI-generated auth configs that
	// may be malformed — the scan proceeds without sessions rather than aborting.
	AuthConfigBestEffort bool
	// SessionFiles are paths to individual session YAML files from --session-file flags
	SessionFiles []string

	// Stateless uses a temporary SQLite database that is deleted after the scan completes.
	// Requires --output to be set. Incompatible with --db.
	Stateless bool
}

// DefaultOptions returns default options for the scanner
func DefaultOptions() *Options {
	return &Options{
		Concurrency:          50,
		MaxPerHost:           20,
		Timeout:              15 * time.Second,
		Retries:              1,
		MaxHostError:         30,
		MaxFindingsPerModule: 10,
		PassiveModules:       []string{"all"},
		ClusterRequests:      true,
		ShutdownTimeout:      30 * time.Second,
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
	case ".jsonl", ".html", ".json":
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
	default:
		return basePath
	}
}
