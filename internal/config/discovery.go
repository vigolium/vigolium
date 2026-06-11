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
	// absent YAML (nil) means use the default (all on). When ConfirmRequired is
	// true the engine only sweeps the wordlist for an extension (.php/.aspx/
	// .jsp/.action/.cgi/…) after confirming the app serves it as a valid route.
	ConfirmRequired       *bool    `yaml:"confirm_required"`        // nil = default (true)
	ConfirmViaObserved    *bool    `yaml:"confirm_via_observed"`    // confirm from observed URLs; nil = true
	ConfirmViaFingerprint *bool    `yaml:"confirm_via_fingerprint"` // confirm from response/cookie fingerprint; nil = true
	ConfirmViaProbe       *bool    `yaml:"confirm_via_probe"`       // confirm via active soft-404 differential probe; nil = true
	Candidates            []string `yaml:"candidates"`              // candidate extensions (no dot); empty = built-in
	ProbeFilenames        []string `yaml:"probe_filenames"`         // probe base names; empty = built-in
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

	return nil
}
