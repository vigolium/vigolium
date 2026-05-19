package config

// ScopeConfig defines which HTTP records are in scope for scanning.
// Each rule is evaluated independently; all must pass (AND logic).
// Exclude takes priority over include.
type ScopeConfig struct {
	// AppliedOnIngest controls whether scope rules are also enforced during
	// ingestion. When true, out-of-scope requests are rejected before being
	// saved to the database. When false (default), all requests are saved but
	// out-of-scope records are skipped during scanning.
	AppliedOnIngest bool `yaml:"applied_on_ingest" json:"applied_on_ingest"`

	// CLIOriginMode restricts which hosts are in scope based on CLI target origins.
	// Modes:
	//   "relaxed"  — host must contain the target's keyword (e.g. "example") (default)
	//   "all"      — no origin restriction
	//   "balanced" — host must share the target's eTLD+1 (e.g. *.example.com)
	//   "strict"   — host must exactly match the target host
	// IP targets always use exact match regardless of mode.
	CLIOriginMode       string    `yaml:"cli_origin_mode" json:"cli_origin_mode"`
	Host                ScopeRule `yaml:"host" json:"host"`
	Path                ScopeRule `yaml:"path" json:"path"`
	StatusCode          ScopeRule `yaml:"status_code" json:"status_code"`
	RequestContentType  ScopeRule `yaml:"request_content_type" json:"request_content_type"`
	ResponseContentType ScopeRule `yaml:"response_content_type" json:"response_content_type"`
	RequestString       ScopeRule `yaml:"request_string" json:"request_string"`
	ResponseString      ScopeRule `yaml:"response_string" json:"response_string"`

	// MaxRequestBodySize is the maximum request body size in bytes.
	// Bodies exceeding this limit are handled according to BodySizeExceededAction.
	// 0 means unlimited. Default: 1048576 (1 MB).
	MaxRequestBodySize int64 `yaml:"max_request_body_size" json:"max_request_body_size"`

	// MaxResponseBodySize is the maximum response body size in bytes.
	// Bodies exceeding this limit are handled according to BodySizeExceededAction.
	// 0 means unlimited. Default: 524288000 (500 MB).
	MaxResponseBodySize int64 `yaml:"max_response_body_size" json:"max_response_body_size"`

	// BodySizeExceededAction controls what happens when a body exceeds its size limit.
	// Values: "truncate" (default) — truncate body to limit, save and scan;
	//         "drop" — discard the item entirely (no save, no scan);
	//         "skip-scan" — save truncated body to DB but skip scanning modules.
	BodySizeExceededAction string `yaml:"body_size_exceeded_action" json:"body_size_exceeded_action"`

	// IgnoreStaticFile when true automatically skips URLs whose path ends
	// with a known static-asset extension (images, fonts, video, audio, etc.).
	// Enabled by default to reduce noise and improve scan performance.
	IgnoreStaticFile bool `yaml:"ignore_static_file" json:"ignore_static_file"`

	// IgnoreStaticContentType maps category names to lists of file extensions
	// that should be treated as static assets (e.g. "images" → [".jpg", ".png"]).
	// Only used when IgnoreStaticFile is true.
	IgnoreStaticContentType map[string][]string `yaml:"ignore_static_content_type" json:"ignore_static_content_type"`
}

// ScopeRule defines include/exclude patterns for a single scope component.
type ScopeRule struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// DefaultScopeConfig returns the default scope configuration.
// By default everything is in scope: include ["*"], exclude [].
// String rules default to empty include (match all when empty).
// Static file filtering is enabled by default.
func DefaultScopeConfig() *ScopeConfig {
	return &ScopeConfig{
		AppliedOnIngest:         false,
		CLIOriginMode:           "relaxed",
		Host:                    ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		Path:                    ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		StatusCode:              ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		RequestContentType:      ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		ResponseContentType:     ScopeRule{Include: []string{"*"}, Exclude: []string{}},
		RequestString:           ScopeRule{Include: []string{}, Exclude: []string{}},
		ResponseString:          ScopeRule{Include: []string{}, Exclude: []string{}},
		MaxRequestBodySize:      1 << 20,         // 1 MB
		MaxResponseBodySize:     500 * (1 << 20), // 500 MB
		BodySizeExceededAction:  "truncate",
		IgnoreStaticFile:        true,
		IgnoreStaticContentType: DefaultStaticExtensions(),
	}
}

// DefaultStaticExtensions returns the default map of static asset categories
// to file extensions. Used when IgnoreStaticFile is enabled.
func DefaultStaticExtensions() map[string][]string {
	return map[string][]string{
		"fonts": {
			".ttf", ".otf", ".woff", ".woff2", ".eot",
			".pfa", ".pfb", ".fnt", ".bdf", ".psf",
			".snf", ".otc", ".ttc", ".afm", ".pfm",
		},
		"images": {
			".jpg", ".jpeg", ".png", ".gif", ".bmp",
			".tif", ".tiff", ".webp", ".avif", ".heic",
			".heif", ".ico", ".cur", ".psd", ".raw",
			".cr2", ".nef", ".arw", ".dng",
		},
		"vector_images": {
			".svg", ".ai", ".eps", ".cdr",
		},
		"video": {
			".mp4", ".m4v", ".mov", ".avi", ".wmv",
			".flv", ".webm", ".mkv", ".3gp", ".3g2",
			".mpeg", ".mpg", ".ts", ".m2ts", ".ogv",
			".vob", ".rm", ".rmvb",
		},
		"audio": {
			".mp3", ".wav", ".ogg", ".aac", ".flac",
			".m4a", ".wma", ".mid", ".midi", ".amr",
			".opus", ".aiff",
		},
	}
}
