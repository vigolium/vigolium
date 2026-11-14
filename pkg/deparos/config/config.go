package config

import (
	nethttp "net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Config represents all content discovery configuration.
type Config struct {
	Target     TargetConfig    `json:"target" validate:"required"`
	Filenames  FilenameConfig  `json:"filenames"`
	Extensions ExtensionConfig `json:"extensions"`
	Engine     EngineConfig    `json:"engine"`
	JSTangle   JSTangleConfig  `json:"jstangle" yaml:"jstangle"`
	Sitemap    SitemapConfig   `json:"sitemap" yaml:"sitemap"`
	Modules    ModuleConfig    `json:"modules"`
}

// SitemapConfig controls the sitemap source: at engine start, discovery fetches
// the sitemaps robots.txt names (or probes /sitemap.xml and /sitemap_index.xml
// when it names none), streams every <loc>, feeds each in-scope path to the
// observed-path wordlist, and spiders a path-shape sample of them.
//
// The zero value is disabled; NewDefaultConfig turns it on.
type SitemapConfig struct {
	Enabled     bool `json:"enabled" yaml:"enabled"`
	MaxURLs     int  `json:"max_urls" yaml:"max_urls"`         // sampled locs spidered per target; 0 = 2000. Hitting it notes the sitemap_cap limit
	PerShape    int  `json:"per_shape" yaml:"per_shape"`       // sampled locs per host + path shape; 0 = 3
	FollowIndex bool `json:"follow_index" yaml:"follow_index"` // fetch <sitemapindex> children (depth <= 2, <= 16 per index)
}

// EffectiveMaxURLs returns MaxURLs, or DefaultSitemapMaxURLs when it is unset.
func (c SitemapConfig) EffectiveMaxURLs() int {
	if c.MaxURLs > 0 {
		return c.MaxURLs
	}
	return DefaultSitemapMaxURLs
}

// EffectivePerShape returns PerShape, or DefaultSitemapPerShape when it is unset.
func (c SitemapConfig) EffectivePerShape() int {
	if c.PerShape > 0 {
		return c.PerShape
	}
	return DefaultSitemapPerShape
}

// JSTangleConfig exposes safe, high-level JavaScript intelligence controls.
// Byte-heavy internals remain owned by the shared jstangle service.
type JSTangleConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	ReplayMode        string        `json:"replay_mode" yaml:"replay_mode"`
	ReplaySafety      string        `json:"replay_safety" yaml:"replay_safety"`
	SourceMaps        bool          `json:"source_maps" yaml:"source_maps"`
	AssetGraph        bool          `json:"asset_graph" yaml:"asset_graph"`
	ProtocolHandshake bool          `json:"protocol_handshake" yaml:"protocol_handshake"`
	WorkerCount       int           `json:"worker_count" yaml:"worker_count"`
	MemoryBudgetMB    int           `json:"memory_budget_mb" yaml:"memory_budget_mb"`
	CacheMB           int           `json:"cache_mb" yaml:"cache_mb"`
	WorkerMaxJobs     int           `json:"worker_max_jobs" yaml:"worker_max_jobs"`
	WorkerMaxRSSMB    int           `json:"worker_max_rss_mb" yaml:"worker_max_rss_mb"`
	JobTimeout        time.Duration `json:"job_timeout" yaml:"job_timeout"`
	NormalInputMB     int           `json:"normal_input_mb" yaml:"normal_input_mb"`
	MaxASTInputMB     int           `json:"max_ast_input_mb" yaml:"max_ast_input_mb"`
	// MaxUnpackInputMB bounds the unminify/unpack pass, which reads source and
	// never builds an AST. Above MaxASTInputMB, a beautify request is still
	// dispatched up to this ceiling instead of falling back to regex alone.
	MaxUnpackInputMB   int `json:"max_unpack_input_mb" yaml:"max_unpack_input_mb"`
	HardInputMB        int `json:"hard_input_mb" yaml:"hard_input_mb"`
	MaxRequestsPerFile int `json:"max_requests_per_file" yaml:"max_requests_per_file"`
	MaxASTNodes        int `json:"max_ast_nodes" yaml:"max_ast_nodes"`
	MaxAssetDepth      int `json:"max_asset_depth" yaml:"max_asset_depth"`
	MaxAssetsPerParent int `json:"max_assets_per_parent" yaml:"max_assets_per_parent"`
	MaxAssetsPerHost   int `json:"max_assets_per_host" yaml:"max_assets_per_host"`
	MaxAssetsTotal     int `json:"max_assets_total" yaml:"max_assets_total"`
	// MaxChunksPerRuntime bounds the loader-rendered chunks (webpack/Vite) one
	// bundle may add to the asset graph, in place of MaxAssetsPerParent. 0 = 512.
	MaxChunksPerRuntime int `json:"max_chunks_per_runtime" yaml:"max_chunks_per_runtime"`
}

// TargetConfig defines where and what to discover.
type TargetConfig struct {
	StartURL  string          `json:"start_url" validate:"required,url"`
	Mode      DiscoveryMode   `json:"mode" validate:"required,oneof=files_and_dirs files_only dirs_only"`
	Recursion RecursionConfig `json:"recursion"`
	ScopeMode string          `json:"scope_mode" validate:"oneof=any subdomain exact"`
}

// RecursionConfig controls directory traversal depth.
type RecursionConfig struct {
	Enabled  bool  `json:"enabled"`
	MaxDepth int16 `json:"max_depth" validate:"min=1,max=32767"`
}

// FilenameConfig defines filename sources.
type FilenameConfig struct {
	Wordlists                  WordlistConfig        `json:"wordlists"`
	UseObservedNames           bool                  `json:"use_observed_names"`
	UseObservedPaths           bool                  `json:"use_observed_paths"`
	UseObservedFiles           bool                  `json:"use_observed_files"` // Test full observed filenames (e.g., "app.b5ca88ec.js")
	EnableNumericFuzzing       bool                  `json:"enable_numeric_fuzzing"`
	EnableMalformedPathProbe   bool                  `json:"enable_malformed_path_probe"`
	MalformedPathProbePayloads [][]byte              `json:"-"`                   // Injected by caller, not serialized
	WordlistExtraction         WordlistExtractConfig `json:"wordlist_extraction"` // Extract words from response bodies
}

// WordlistExtractConfig controls runtime wordlist extraction from response bodies.
type WordlistExtractConfig struct {
	Enabled         bool   `json:"enabled"`          // Enable wordlist extraction from response bodies
	DelimExceptions string `json:"delim_exceptions"` // Extra chars to include in tokens (e.g., "-_")
	MaxCombine      int    `json:"max_combine"`      // Max segments to combine (default: 2)
	MinLength       int    `json:"min_length"`       // Min token length (default: 3)
	MaxLength       int    `json:"max_length"`       // Max token length (default: 64)
}

// WordlistConfig holds paths to wordlist files.
// Empty path = wordlist disabled. Non-empty path = wordlist enabled.
type WordlistConfig struct {
	ShortFilePath    string `json:"short_file_path" validate:"omitempty,file"`
	LongFilePath     string `json:"long_file_path" validate:"omitempty,file"`
	ShortDirPath     string `json:"short_dir_path" validate:"omitempty,file"`
	LongDirPath      string `json:"long_dir_path" validate:"omitempty,file"`
	FuzzWordlistPath string `json:"fuzz_wordlist_path" validate:"omitempty,file"`

	// FuzzWordlistPaths are the /FUZZ wordlists, streamed one after another
	// with each word tried once across all of them. When empty,
	// FuzzWordlistPath (the single-file form) is used instead.
	FuzzWordlistPaths []string `json:"fuzz_wordlist_paths,omitempty" validate:"omitempty,dive,file"`
}

// HasShortFiles returns true if short file wordlist is configured.
func (w *WordlistConfig) HasShortFiles() bool { return w.ShortFilePath != "" }

// HasLongFiles returns true if long file wordlist is configured.
func (w *WordlistConfig) HasLongFiles() bool { return w.LongFilePath != "" }

// HasShortDirs returns true if short directory wordlist is configured.
func (w *WordlistConfig) HasShortDirs() bool { return w.ShortDirPath != "" }

// HasLongDirs returns true if long directory wordlist is configured.
func (w *WordlistConfig) HasLongDirs() bool { return w.LongDirPath != "" }

// FuzzWordlists returns the configured fuzz wordlist paths: FuzzWordlistPaths
// when set (empty entries dropped), else the legacy single FuzzWordlistPath.
func (w *WordlistConfig) FuzzWordlists() []string {
	var out []string
	for _, p := range w.FuzzWordlistPaths {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 && w.FuzzWordlistPath != "" {
		out = append(out, w.FuzzWordlistPath)
	}
	return out
}

// HasFuzzWordlist returns true if at least one fuzz wordlist is configured.
func (w *WordlistConfig) HasFuzzWordlist() bool { return len(w.FuzzWordlists()) > 0 }

// ExtensionConfig controls file extension testing.
type ExtensionConfig struct {
	TestCustom           bool     `json:"test_custom"`
	CustomList           []string `json:"custom_list"`
	TestObserved         bool     `json:"test_observed"`
	TestBackupExtensions bool     `json:"test_backup_extensions"`
	BackupExtensions     []string `json:"backup_extensions"`
	TestNoExtension      bool     `json:"test_no_extension"`

	// ConfirmRequired gates server-side extension fuzzing behind a confirmation
	// step: instead of blindly sweeping the wordlist with every CustomList
	// extension, the engine only fuzzes an extension once it has confirmed the
	// application serves it as a valid route. When true the static CustomList
	// fuzzing is disabled and all extension fuzzing flows through the confirm
	// pipeline (observed URLs / fingerprint / active probe). When false the
	// legacy always-on CustomList behaviour applies.
	ConfirmRequired bool `json:"confirm_required"`
	// ConfirmViaObserved confirms an extension when a URL the application
	// genuinely references bears it: the start URL, a spidered link from an HTML
	// attribute / meta-refresh / HTTP header / robots.txt, a sitemap entry, or a
	// file actually fetched and confirmed (non-soft-404). Path-like strings
	// scavenged from JS/HTML body text (inline/JS-string extractors) do NOT
	// count — they are not proof the server serves that extension — and on a
	// JS-shell SPA the observed source is suppressed entirely, since the index
	// shell is served for every path. See Engine.extensionConfirmAllowed.
	ConfirmViaObserved bool `json:"confirm_via_observed"`
	// ConfirmViaFingerprint confirms an extension when the start URL's response
	// headers/cookies fingerprint a stack known to serve it (PHPSESSID → php,
	// JSESSIONID → jsp/action, ASP.NET_SessionId → aspx/ashx, …).
	ConfirmViaFingerprint bool `json:"confirm_via_fingerprint"`
	// ConfirmViaProbe confirms an extension via an active soft-404 differential
	// probe: it GETs guessed filenames (index/default/login.<ext>) and confirms
	// if the analyzer reports a non-soft-404 hit. This is a brute-force guess, not
	// something the site revealed, so it false-positives on catch-all / SPA-shell
	// hosts that answer 200 for any path — confirming (and then wordlist-fuzzing)
	// extensions the server does not actually run. OFF by default; opt in only for
	// rewrite-heavy apps where no link or header reveals the stack.
	ConfirmViaProbe bool `json:"confirm_via_probe"`
	// Candidates is the set of server-side extensions eligible for confirmation
	// + fuzzing (no leading dot). Only extensions in this set are ever probed,
	// fingerprint-mapped, or wordlist-swept under ConfirmRequired.
	Candidates []string `json:"candidates"`
	// ProbeFilenames are the high-signal base names tried per candidate during
	// the active probe (no extension). Empty = built-in default.
	ProbeFilenames []string `json:"probe_filenames"`

	// JSBundleSweep enables a curated, SPA-gated sweep for common base names,
	// each probed as both .js (bundles) and .json (sibling config/data) —
	// main.js, admin.js, config.json, settings.json, … — on monolith /
	// server-rendered apps. Confirmed hits are fed to the JS-fetch pipeline for
	// endpoint and secret extraction. The sweep is skipped when the start page
	// fingerprints as a JS-shell SPA (Next.js/React/Angular/Vue/Svelte), whose
	// bundles are content-hashed (main.a1b2c3.js) and therefore unguessable —
	// and already linked + harvested. See discovery/js_bundle_sweep.go.
	JSBundleSweep bool `json:"js_bundle_sweep"`
	// JSBundleNames overrides the built-in curated name list (no leading dot, no
	// extension — both .js and .json are appended). Empty = DefaultJSBundleNames.
	JSBundleNames []string `json:"js_bundle_names"`
}

// EffectiveCustomList returns the custom extensions to statically sweep with the
// wordlist. It is empty when custom fuzzing is disabled (TestCustom) or gated
// behind confirmation (ConfirmRequired) — in the latter case extensions are
// swept only after being confirmed, via the observed-extension task path.
func (ec ExtensionConfig) EffectiveCustomList() []string {
	if !ec.TestCustom || ec.ConfirmRequired {
		return nil
	}
	return ec.CustomList
}

// EngineConfig controls discovery execution.
type EngineConfig struct {
	CaseSensitivity         CaseSensitivityMode `json:"case_sensitivity" validate:"oneof=sensitive insensitive auto_detect"`
	DiscoveryThreads        int                 `json:"discovery_threads" validate:"min=1,max=255"`
	Timeout                 time.Duration       `json:"timeout" validate:"min=1s,max=300s"`               // HTTP per-request timeout
	SkipFingerprintLearning bool                `json:"skip_fingerprint_learning"`                        // Skip 404 fingerprint learning (for tests)
	MaxConsecutiveErrors    int                 `json:"max_consecutive_errors"`                           // Exit after N consecutive network errors (0 = disabled)
	MaxConsecutiveWAFBlocks int                 `json:"max_consecutive_waf_blocks"`                       // Exit after N consecutive WAF/CDN blocks (0 = disabled)
	CustomHeaders           map[string]string   `json:"custom_headers"`                                   // User-defined HTTP request headers
	ObservedMaxItems        int                 `json:"observed_max_items"`                               // Max items per observed provider (0 = default 50000)
	DisableSecretScan       bool                `json:"disable_secret_scan"`                              // Disable native secret scanning during discovery
	EnableCookieJar         bool                `json:"enable_cookie_jar"`                                // Enable cookie jar for session persistence
	ProxyURL                string              `json:"proxy_url"`                                        // HTTP proxy URL for discovery requests
	JSTangleConcurrency     int                 `yaml:"jstangle_concurrency" json:"jstangle_concurrency"` // Deprecated: alias of jstangle.worker_count, used only when that is 0; see Config.JSTangleWorkerCount
	PrefixBreaker           PrefixBreakerConfig `json:"prefix_breaker"`                                   // Per-prefix circuit breaker for soft-404 / trap directories

	// BruteForceThreads is the worker count for wordlist and FUZZ-template
	// requests, the brute-force half of discovery. Everything else (spider,
	// observed-word and extension variants, JS fetches, validation probes)
	// keeps DiscoveryThreads. 0 = DiscoveryThreads (one shared pace).
	BruteForceThreads int `json:"brute_force_threads" validate:"min=0,max=1024"`
	// Protocol is the wire protocol policy for the engine's requests:
	// "auto" (HTTP/3, then HTTP/2, then HTTP/1.1, pinned per origin), "http1",
	// "http2" or "http3"; "" = http1, the engine's historical behavior. One
	// protocol per origin for the whole engine, learner included, so soft-404
	// fingerprints are compared against responses of the same protocol.
	Protocol string `json:"protocol"`

	// RequestFilter is consulted before every request leaves the engine's HTTP
	// client: returning false refuses it with deparos/http.ErrRequestFiltered
	// instead of sending it. The engine also derives the spider's scope exclusion
	// from it, so a refused URL is never queued in the first place.
	//
	// It carries the caller's EXPLICIT denials (an operator's scope.host.exclude /
	// scope.path.exclude), not the scope mode — Target.ScopeMode still decides how
	// wide the crawl goes. nil = no denials.
	//
	// Not serialized: a runtime policy hook, not configuration.
	RequestFilter func(*url.URL) bool `json:"-"`

	// MethodFilter, when set, refuses a request whose method the scan's traffic
	// policy does not allow (scope.methods) the same way RequestFilter
	// refuses an excluded URL. nil = every method.
	MethodFilter func(method string) bool `json:"-"`

	// FormSafety is the replay-safety policy for HTML form submission during
	// discovery: metadata-only, read-only, safe-baseline or
	// state-changing. Empty uses jstangle.replay_safety. The runner sets
	// metadata-only when the browser policy denies form submission.
	FormSafety string `json:"form_safety,omitempty" yaml:"form_safety,omitempty"`

	// RequestCounter, when set, is incremented once per physical HTTP attempt the
	// engine makes, retries included. Owned by the caller; the engine only adds to
	// it. It exists so the phase driving a crawl can report the traffic that crawl
	// actually generated — the engine has its own client, so a caller watching a
	// shared requester sees almost nothing.
	//
	// Not serialized: a runtime output channel, not configuration.
	RequestCounter *atomic.Int64 `json:"-"`

	// RequestsPerSecond caps the engine's outgoing request rate with a token
	// bucket. 0 (the default) means unpaced, which is what discovery has always
	// been — DiscoveryThreads was the only throttle. Set it only when the caller
	// has an EXPLICIT rate to enforce: the bucket's own fallback turns a
	// misconfigured value into 10 rps, which would silently crawl ~100x slower
	// than the thread count implies.
	//
	// Not serialized: resolved from the caller's pace settings, which have their
	// own config surface.
	RequestsPerSecond int `json:"-"`

	// Egress, when set, wraps the engine's transport INSIDE its retry middleware,
	// so every physical attempt (each retry included) is admitted by the caller's
	// egress policy before it goes out. Vigolium passes its scan gate here: the
	// scan's host slots and dead-host quarantine, plus a discovery-wide token
	// bucket shared by every concurrent discovery target. When the gate carries
	// the rate, leave RequestsPerSecond at 0 so the request is not paced twice.
	//
	// A refusal it returns must not be retryable (see deparos/http.IsRetryable).
	// Not serialized: a runtime hook, not configuration.
	Egress func(nethttp.RoundTripper) nethttp.RoundTripper `json:"-"`
}

// PrefixBreakerConfig tunes the per-prefix discovery circuit breaker.
// When responses under a given path prefix become overwhelmingly uniform
// (same status, content-type, and length-bucket), the breaker trips and
// further discovery probes / recursion under that prefix are skipped.
type PrefixBreakerConfig struct {
	Enabled        bool    `json:"enabled"`         // Master switch (default: true)
	MinSamples     int     `json:"min_samples"`     // Observations required before trip is possible
	TripRatio      float64 `json:"trip_ratio"`      // Share (0..1] of dominant tuple required to trip
	PrefixSegments int     `json:"prefix_segments"` // Path segments forming the prefix key (1 = /ftp, 2 = /ftp/api)
	LengthBucket   int64   `json:"length_bucket"`   // Body-length bucket width in bytes
}

// Enums.

// DiscoveryMode controls what types of resources to discover.
type DiscoveryMode string

const (
	ModeFilesAndDirs DiscoveryMode = "files_and_dirs"
	ModeFilesOnly    DiscoveryMode = "files_only"
	ModeDirsOnly     DiscoveryMode = "dirs_only"
)

// CaseSensitivityMode controls filename matching.
type CaseSensitivityMode string

const (
	CaseSensitive   CaseSensitivityMode = "sensitive"
	CaseInsensitive CaseSensitivityMode = "insensitive"
	CaseAutoDetect  CaseSensitivityMode = "auto_detect"
)

// warnJSTangleConcurrencyOnce keeps the deprecation warning to one line per
// process: discovery builds an engine per target from the same config.
var warnJSTangleConcurrencyOnce sync.Once

// JSTangleWorkerCount resolves the jstangle worker count: jstangle.worker_count,
// or the deprecated engine.jstangle_concurrency alias when worker_count is 0
// (logging a deprecation warning once). 0 lets the service derive the count.
func (c *Config) JSTangleWorkerCount() int {
	if c.JSTangle.WorkerCount > 0 || c.Engine.JSTangleConcurrency <= 0 {
		return c.JSTangle.WorkerCount
	}
	warnJSTangleConcurrencyOnce.Do(func() {
		zap.L().Warn("deparos engine.jstangle_concurrency is deprecated; set jstangle.worker_count instead",
			zap.Int("jstangle_concurrency", c.Engine.JSTangleConcurrency))
	})
	return c.Engine.JSTangleConcurrency
}
