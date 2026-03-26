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
	MalformedPathProbePayloads [][]byte              `json:"-"` // Injected by caller, not serialized
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
	ShortFilePath     string `json:"short_file_path" validate:"omitempty,file"`
	LongFilePath      string `json:"long_file_path" validate:"omitempty,file"`
	ShortDirPath      string `json:"short_dir_path" validate:"omitempty,file"`
	LongDirPath       string `json:"long_dir_path" validate:"omitempty,file"`
	FuzzWordlistPath  string `json:"fuzz_wordlist_path" validate:"omitempty,file"`
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
	TestCustom      bool     `json:"test_custom"`
	CustomList      []string `json:"custom_list"`
	TestObserved    bool     `json:"test_observed"`
	TestBackupExtensions bool     `json:"test_backup_extensions"`
	BackupExtensions     []string `json:"backup_extensions"`
	TestNoExtension bool     `json:"test_no_extension"`
}

// EngineConfig controls discovery execution.
type EngineConfig struct {
	CaseSensitivity         CaseSensitivityMode `json:"case_sensitivity" validate:"oneof=sensitive insensitive auto_detect"`
	DiscoveryThreads        int                 `json:"discovery_threads" validate:"min=1,max=255"`
	Timeout                 time.Duration       `json:"timeout" validate:"min=1s,max=300s"` // HTTP per-request timeout
	SkipFingerprintLearning bool                `json:"skip_fingerprint_learning"`          // Skip 404 fingerprint learning (for tests)
	MaxConsecutiveErrors    int                 `json:"max_consecutive_errors"`             // Exit after N consecutive network errors (0 = disabled)
	MaxConsecutiveWAFBlocks int                 `json:"max_consecutive_waf_blocks"`         // Exit after N consecutive WAF/CDN blocks (0 = disabled)
	CustomHeaders           map[string]string   `json:"custom_headers"`                     // User-defined HTTP request headers
	ObservedMaxItems        int                 `json:"observed_max_items"`                 // Max items per observed provider (0 = default 50000)
	DisableKingfisher       bool                `json:"disable_kingfisher"`                 // Disable kingfisher secret scanning
	EnableCookieJar         bool                `json:"enable_cookie_jar"`                  // Enable cookie jar for session persistence
	ProxyURL                string              `json:"proxy_url"`                          // HTTP proxy URL for discovery requests
	JSScanConcurrency       int                 `yaml:"jsscan_concurrency" json:"jsscan_concurrency"` // Max concurrent jsscan analyses (0 = runtime.NumCPU())
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
