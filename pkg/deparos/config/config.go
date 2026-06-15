package config

import (
	"time"
)

// Config represents all content discovery configuration.
type Config struct {
	Target     TargetConfig    `json:"target" validate:"required"`
	Filenames  FilenameConfig  `json:"filenames"`
	Extensions ExtensionConfig `json:"extensions"`
	Engine     EngineConfig    `json:"engine"`
	Modules    ModuleConfig    `json:"modules"`
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
}

// HasShortFiles returns true if short file wordlist is configured.
func (w *WordlistConfig) HasShortFiles() bool { return w.ShortFilePath != "" }

// HasLongFiles returns true if long file wordlist is configured.
func (w *WordlistConfig) HasLongFiles() bool { return w.LongFilePath != "" }

// HasShortDirs returns true if short directory wordlist is configured.
func (w *WordlistConfig) HasShortDirs() bool { return w.ShortDirPath != "" }

// HasLongDirs returns true if long directory wordlist is configured.
func (w *WordlistConfig) HasLongDirs() bool { return w.LongDirPath != "" }

// HasFuzzWordlist returns true if fuzz wordlist is configured.
func (w *WordlistConfig) HasFuzzWordlist() bool { return w.FuzzWordlistPath != "" }

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
	Timeout                 time.Duration       `json:"timeout" validate:"min=1s,max=300s"`           // HTTP per-request timeout
	SkipFingerprintLearning bool                `json:"skip_fingerprint_learning"`                    // Skip 404 fingerprint learning (for tests)
	MaxConsecutiveErrors    int                 `json:"max_consecutive_errors"`                       // Exit after N consecutive network errors (0 = disabled)
	MaxConsecutiveWAFBlocks int                 `json:"max_consecutive_waf_blocks"`                   // Exit after N consecutive WAF/CDN blocks (0 = disabled)
	CustomHeaders           map[string]string   `json:"custom_headers"`                               // User-defined HTTP request headers
	ObservedMaxItems        int                 `json:"observed_max_items"`                           // Max items per observed provider (0 = default 50000)
	DisableKingfisher       bool                `json:"disable_kingfisher"`                           // Disable kingfisher secret scanning
	EnableCookieJar         bool                `json:"enable_cookie_jar"`                            // Enable cookie jar for session persistence
	ProxyURL                string              `json:"proxy_url"`                                    // HTTP proxy URL for discovery requests
	JSScanConcurrency       int                 `yaml:"jsscan_concurrency" json:"jsscan_concurrency"` // Max concurrent jsscan analyses (0 = runtime.NumCPU())
	PrefixBreaker           PrefixBreakerConfig `json:"prefix_breaker"`                               // Per-prefix circuit breaker for soft-404 / trap directories
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
