package config

import (
	"fmt"
	"time"
)

// DiscoveryConfig holds configuration for deparos content discovery.
type DiscoveryConfig struct {
	Mode                     string                   `yaml:"mode"`
	ScopeMode                string                   `yaml:"scope_mode"`
	Recursion                DiscoveryRecursionConfig `yaml:"recursion"`
	Wordlists                DiscoveryWordlistConfig  `yaml:"wordlists"`
	Extensions               DiscoveryExtensionConfig `yaml:"extensions"`
	Engine                   DiscoveryEngineConfig    `yaml:"engine"`
	SaveResponseBody         bool                     `yaml:"save_response_body"`
	EnableMalformedPathProbe bool                     `yaml:"enable_malformed_path_probe"`
	DedupClusterCap          *int                     `yaml:"dedup_cluster_cap"`   // cap near-identical discovery responses (same host/status/content-type, size & words within 0.5%) per cluster; nil=default(10), 0=disabled, N=keep at most N
	AutoFuzzLowYield         *bool                    `yaml:"auto_fuzz_low_yield"` // auto-enable FUZZ fuzzing on the original target when spidering came up low-yield or hit an SSO/login wall; nil=default(on)
	EnrichTargets            bool                     `yaml:"enrich_targets"`      // enrich discovery targets with paths from previous phases (spidering, external harvest)
	ExpandSeedParents        bool                     `yaml:"expand_seed_parents"` // expand each seed URL into its parent directories (e.g., /a/b/c -> /, /a/, /a/b/, /a/b/c) and feed them as additional targets to discovery and spidering
	PassiveModuleTags        []string                 `yaml:"passive_module_tags"` // run passive modules matching these tags during discovery (e.g., ["fingerprint"])
	ReSpider                 DiscoveryReSpiderConfig  `yaml:"respider"`            // targeted re-spider of rich/SPA routes found after discovery dedup
	DeparosDedup             DeparosDedupConfig       `yaml:"deparos_dedup"`       // post-discovery status-retention + reflected-URL-robust record dedup
}

// DeparosDedupConfig controls the post-discovery cleanup of stored deparos
// records, running after the discovery phase over the full record set (in
// addition to the in-engine per-target hard dedup and the soft-dedup pass):
//
//   - a status-retention policy that drops 4xx discovery records (a fuzzed path
//     the server rejects with a client error is not a discovered resource),
//     keeping a single representative per host for "auth wall exists" statuses;
//   - reflected-URL-robust dedup that collapses records differing only by an
//     echoed request URL/path or per-request dynamic tokens.
type DeparosDedupConfig struct {
	Enabled            *bool `yaml:"enabled"`             // nil = default (true)
	DropClientErrors   *bool `yaml:"drop_client_errors"`  // drop 4xx discovery records; nil = default (true)
	KeepOnePerHost     []int `yaml:"keep_one_per_host"`   // statuses collapsed to one representative per host instead of dropped; nil = default ([401]); empty slice = collapse none
	NormalizeReflected *bool `yaml:"normalize_reflected"` // collapse records differing only by a reflected URL/path or dynamic tokens; nil = default (true)
}

// IsEnabled reports whether the post-discovery deparos dedup runs (default on).
func (c *DeparosDedupConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// DropClientErrorsEnabled reports whether 4xx discovery records are dropped
// (default on).
func (c *DeparosDedupConfig) DropClientErrorsEnabled() bool {
	return c.DropClientErrors == nil || *c.DropClientErrors
}

// NormalizeReflectedEnabled reports whether reflected-URL-robust dedup runs
// (default on).
func (c *DeparosDedupConfig) NormalizeReflectedEnabled() bool {
	return c.NormalizeReflected == nil || *c.NormalizeReflected
}

// KeepOneStatuses returns the statuses collapsed to a single record per host
// rather than dropped. nil (absent YAML) defaults to {401}; an explicit empty
// slice keeps the default off (collapse nothing, so every 4xx is dropped).
func (c *DeparosDedupConfig) KeepOneStatuses() []int {
	if c.KeepOnePerHost == nil {
		return []int{401}
	}
	return c.KeepOnePerHost
}

// DiscoveryReSpiderConfig controls the targeted re-spider step that runs after
// discovery dedup. Discovery (fuzzing/jsscan/linkfinder) can surface new routes
// (e.g. /ui/, /console/) after the one-shot browser spidering already ran. When
// such a route's already-fetched response looks like a JS/SPA shell or an
// interactive page (and not a login/SSO wall), this step re-crawls it with a
// real browser on a tight budget so its client-rendered routes enter
// http_records and get dynamic-assessed. Caps keep the browser spend bounded.
type DiscoveryReSpiderConfig struct {
	Enabled            *bool  `yaml:"enabled"`               // nil = default (true)
	MaxSeedsPerHost    int    `yaml:"max_seeds_per_host"`    // per-host seed cap; 0 = default (3)
	MaxSeedsTotal      int    `yaml:"max_seeds_total"`       // overall seed cap; 0 = default (10)
	PerSeedMaxDuration string `yaml:"per_seed_max_duration"` // per-seed crawl budget; "" = default (45s)
	PerSeedMaxStates   int    `yaml:"per_seed_max_states"`   // per-seed state cap; 0 = default (25)
	MaxDepth           int    `yaml:"max_depth"`             // per-seed crawl depth; 0 = default (3)
	StepMaxDuration    string `yaml:"step_max_duration"`     // wall-clock cap for the whole step; "" = default (5m)
}

// IsEnabled reports whether the targeted re-spider step runs (default on).
func (c *DiscoveryReSpiderConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// SeedsPerHost returns the per-host seed cap, applying the default.
func (c *DiscoveryReSpiderConfig) SeedsPerHost() int {
	if c.MaxSeedsPerHost <= 0 {
		return 3
	}
	return c.MaxSeedsPerHost
}

// SeedsTotal returns the overall seed cap, applying the default.
func (c *DiscoveryReSpiderConfig) SeedsTotal() int {
	if c.MaxSeedsTotal <= 0 {
		return 10
	}
	return c.MaxSeedsTotal
}

// PerSeedDuration returns the per-seed crawl budget, applying the default.
func (c *DiscoveryReSpiderConfig) PerSeedDuration() time.Duration {
	if c.PerSeedMaxDuration == "" {
		return 45 * time.Second
	}
	if d, err := time.ParseDuration(c.PerSeedMaxDuration); err == nil && d > 0 {
		return d
	}
	return 45 * time.Second
}

// PerSeedStates returns the per-seed state cap, applying the default.
func (c *DiscoveryReSpiderConfig) PerSeedStates() int {
	if c.PerSeedMaxStates <= 0 {
		return 25
	}
	return c.PerSeedMaxStates
}

// Depth returns the per-seed crawl depth, applying the default.
func (c *DiscoveryReSpiderConfig) Depth() int {
	if c.MaxDepth <= 0 {
		return 3
	}
	return c.MaxDepth
}

// StepDuration returns the wall-clock cap for the whole step, applying the default.
func (c *DiscoveryReSpiderConfig) StepDuration() time.Duration {
	if c.StepMaxDuration == "" {
		return 5 * time.Minute
	}
	if d, err := time.ParseDuration(c.StepMaxDuration); err == nil && d > 0 {
		return d
	}
	return 5 * time.Minute
}

// DiscoveryRecursionConfig controls directory traversal depth.
type DiscoveryRecursionConfig struct {
	Enabled  bool `yaml:"enabled"`
	MaxDepth int  `yaml:"max_depth"`
}

// DiscoveryWordlistConfig holds paths to wordlist files.
type DiscoveryWordlistConfig struct {
	ShortFilePath        string `yaml:"short_file_path"`
	LongFilePath         string `yaml:"long_file_path"`
	ShortDirPath         string `yaml:"short_dir_path"`
	LongDirPath          string `yaml:"long_dir_path"`
	FuzzWordlistPath     string `yaml:"fuzz_wordlist_path"`
	UseObservedNames     bool   `yaml:"use_observed_names"`
	UseObservedPaths     bool   `yaml:"use_observed_paths"`
	UseObservedFiles     bool   `yaml:"use_observed_files"`
	EnableNumericFuzzing bool   `yaml:"enable_numeric_fuzzing"`
}

// DiscoveryExtensionConfig controls file extension testing.
type DiscoveryExtensionConfig struct {
	TestCustom           bool     `yaml:"test_custom"`
	CustomList           []string `yaml:"custom_list"`
	TestObserved         bool     `yaml:"test_observed"`
	TestBackupExtensions bool     `yaml:"test_backup_extensions"`
	BackupExtensions     []string `yaml:"backup_extensions"`
	TestNoExtension      bool     `yaml:"test_no_extension"`

	// Confirmation-gated server-side extension fuzzing. Pointer-bool semantics:
	// absent YAML (nil) means use the default. When ConfirmRequired is true the
	// engine only sweeps the wordlist for an extension (.php/.aspx/.jsp/.action/
	// .cgi/…) after confirming the app serves it as a valid route — confirmation
	// is driven by what the site reveals (observed URLs + tech fingerprint), not
	// by brute-force guessing (the active probe is off by default).
	ConfirmRequired       *bool    `yaml:"confirm_required"`        // nil = default (true)
	ConfirmViaObserved    *bool    `yaml:"confirm_via_observed"`    // confirm from observed URLs; nil = true
	ConfirmViaFingerprint *bool    `yaml:"confirm_via_fingerprint"` // confirm from response/cookie fingerprint; nil = true
	ConfirmViaProbe       *bool    `yaml:"confirm_via_probe"`       // confirm via active brute-force soft-404 probe; nil = false (FP-prone on catch-all hosts)
	Candidates            []string `yaml:"candidates"`              // candidate extensions (no dot); empty = built-in
	ProbeFilenames        []string `yaml:"probe_filenames"`         // probe base names; empty = built-in

	// SPA-gated JS-bundle name sweep: probe common JS bundle names (main.js,
	// admin.js, config.js, …) on monolith / server-rendered apps and feed hits
	// to jsscan. Skipped on JS-shell SPAs (content-hashed, unguessable bundles).
	JSBundleSweep *bool    `yaml:"js_bundle_sweep"` // nil = default (true)
	JSBundleNames []string `yaml:"js_bundle_names"` // override curated names; empty = built-in
}

// DiscoveryEngineConfig controls discovery execution settings.
type DiscoveryEngineConfig struct {
	CaseSensitivity         string                       `yaml:"case_sensitivity"`
	Timeout                 string                       `yaml:"timeout"`
	CustomHeaders           map[string]string            `yaml:"custom_headers"`
	EnableCookieJar         bool                         `yaml:"enable_cookie_jar"`
	MaxConsecutiveErrors    int                          `yaml:"max_consecutive_errors"`
	MaxConsecutiveWAFBlocks int                          `yaml:"max_consecutive_waf_blocks"`
	ObservedMaxItems        int                          `yaml:"observed_max_items"`
	DisableKingfisher       bool                         `yaml:"disable_kingfisher"`
	PrefixBreaker           DiscoveryPrefixBreakerConfig `yaml:"prefix_breaker"`
}

// DiscoveryPrefixBreakerConfig tunes the per-prefix circuit breaker that stops
// discovery from recursing into trap directories (uniform 4xx / soft-200 sinks).
// Pointer-bool semantics aren't used; absent YAML means use defaults from
// pkg/deparos/config/defaults.go.
type DiscoveryPrefixBreakerConfig struct {
	Enabled        *bool   `yaml:"enabled"`         // nil = use deparos default (true)
	MinSamples     int     `yaml:"min_samples"`     // 0 = use deparos default
	TripRatio      float64 `yaml:"trip_ratio"`      // 0 = use deparos default
	PrefixSegments int     `yaml:"prefix_segments"` // 0 = use deparos default
	LengthBucket   int64   `yaml:"length_bucket"`   // 0 = use deparos default
}

// DefaultDiscoveryConfig returns default discovery configuration.
func DefaultDiscoveryConfig() *DiscoveryConfig {
	return &DiscoveryConfig{
		Mode:      "files_and_dirs",
		ScopeMode: "subdomain",
		Recursion: DiscoveryRecursionConfig{
			Enabled:  true,
			MaxDepth: 5,
		},
		Wordlists: DiscoveryWordlistConfig{
			UseObservedNames:     true,
			UseObservedPaths:     true,
			UseObservedFiles:     true,
			EnableNumericFuzzing: false,
		},
		Extensions: DiscoveryExtensionConfig{
			TestCustom:           true,
			TestObserved:         true,
			TestBackupExtensions: true,
			TestNoExtension:      true,
		},
		Engine: DiscoveryEngineConfig{
			CaseSensitivity:  "auto_detect",
			Timeout:          "10s",
			ObservedMaxItems: 4000,
		},
		SaveResponseBody: true,
	}
}

// EngineTimeoutParsed returns the parsed engine timeout. Falls back to 10s on error.
func (c *DiscoveryConfig) EngineTimeoutParsed() time.Duration {
	if c.Engine.Timeout == "" {
		return 10 * time.Second
	}
	d, err := time.ParseDuration(c.Engine.Timeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// Validate checks discovery configuration for errors.
func (c *DiscoveryConfig) Validate() error {
	switch c.Mode {
	case "", "files_and_dirs", "files_only", "dirs_only":
		// valid
	default:
		return fmt.Errorf("discovery.mode: must be files_and_dirs, files_only, or dirs_only, got %q", c.Mode)
	}

	switch c.ScopeMode {
	case "", "any", "subdomain", "exact":
		// valid
	default:
		return fmt.Errorf("discovery.scope_mode: must be any, subdomain, or exact, got %q", c.ScopeMode)
	}

	if c.Recursion.Enabled && c.Recursion.MaxDepth < 1 {
		return fmt.Errorf("discovery.recursion.max_depth must be >= 1 when enabled")
	}

	if c.Engine.Timeout != "" {
		d, err := time.ParseDuration(c.Engine.Timeout)
		if err != nil {
			return fmt.Errorf("discovery.engine.timeout: invalid duration %q: %w", c.Engine.Timeout, err)
		}
		if d < 1*time.Second || d > 300*time.Second {
			return fmt.Errorf("discovery.engine.timeout must be 1s-300s, got %v", d)
		}
	}

	switch c.Engine.CaseSensitivity {
	case "", "auto_detect", "sensitive", "insensitive":
		// valid
	default:
		return fmt.Errorf("discovery.engine.case_sensitivity: must be auto_detect, sensitive, or insensitive, got %q", c.Engine.CaseSensitivity)
	}

	if c.ReSpider.PerSeedMaxDuration != "" {
		if _, err := time.ParseDuration(c.ReSpider.PerSeedMaxDuration); err != nil {
			return fmt.Errorf("discovery.respider.per_seed_max_duration: invalid duration %q: %w", c.ReSpider.PerSeedMaxDuration, err)
		}
	}
	if c.ReSpider.StepMaxDuration != "" {
		if _, err := time.ParseDuration(c.ReSpider.StepMaxDuration); err != nil {
			return fmt.Errorf("discovery.respider.step_max_duration: invalid duration %q: %w", c.ReSpider.StepMaxDuration, err)
		}
	}

	return nil
}
