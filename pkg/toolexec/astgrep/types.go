// Package astgrep provides a structural code search tool using ast-grep for
// extracting routes, parameters, and API endpoints from application source code.
//
// ast-grep provides automatic downloading, caching,
// and a clean Go API with embedded YAML rules for common web frameworks.
//
// # Quick Start
//
// The simplest way to use astgrep is with the package-level ScanDir function:
//
//	result, err := astgrep.ScanDir(ctx, "/path/to/repo", "gin")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, m := range result.Matches {
//	    fmt.Printf("%s:%d — %s\n", m.File, m.Range.Start.Line, m.Text)
//	}
//
// # Binary Caching
//
// The ast-grep binary is resolved in this order:
//  1. System PATH (exec.LookPath("ast-grep"))
//  2. Cached at ~/.cache/ast-grep/ast-grep
//  3. Auto-downloaded from GitHub releases
//
// # Thread Safety
//
// Both Scanner and Downloader are thread-safe for concurrent use.
package astgrep

import (
	"errors"
	"time"

	"github.com/vigolium/vigolium/pkg/toolexec"
)

// Sentinel errors — aliases of toolexec errors for backward compatibility
// plus the package-specific ErrScanFailed.
var (
	ErrBinaryNotFound      = toolexec.ErrBinaryNotFound
	ErrDownloadFailed      = toolexec.ErrDownloadFailed
	ErrExtractionFailed    = toolexec.ErrExtractionFailed
	ErrUnsupportedPlatform = toolexec.ErrUnsupportedPlatform

	// ErrScanFailed indicates the ast-grep scan command failed.
	ErrScanFailed = errors.New("ast-grep scan failed")
)

// Match represents a single ast-grep match from JSON output.
type Match struct {
	ID            string                  `json:"id"`
	Text          string                  `json:"text"`
	Range         MatchRange              `json:"range"`
	File          string                  `json:"file"`
	Language      string                  `json:"language"`
	Message       string                  `json:"message"`
	Severity      string                  `json:"severity"`
	MetaVariables map[string]MetaVariable `json:"metaVariables"`
}

// MatchRange represents the location of a match in a file.
type MatchRange struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Position represents a line/column position in a file.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
	Offset int `json:"offset"`
}

// MetaVariable represents a captured metavariable from an ast-grep match.
type MetaVariable struct {
	Text  string     `json:"text"`
	Range MatchRange `json:"range"`
}

// ScanResult contains the complete output from an ast-grep scan.
type ScanResult struct {
	// Matches is the list of discovered code matches.
	Matches []Match `json:"matches"`

	// ScanDuration is how long the scan took.
	ScanDuration time.Duration `json:"scan_duration"`

	// RuleSet is the framework/rule set used for scanning.
	RuleSet string `json:"rule_set"`
}

// HasMatches returns true if any matches were found.
func (r *ScanResult) HasMatches() bool {
	return len(r.Matches) > 0
}

// Route represents a structured route extracted from ast-grep matches.
type Route struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Params []string `json:"params,omitempty"`
	File   string   `json:"file"`
	Line   int      `json:"line"`
}

// Config configures the ast-grep scanner behavior.
type Config struct {
	// CacheDir overrides the default cache directory (~/.cache/ast-grep/).
	CacheDir string

	// Version specifies a specific ast-grep version to use.
	// If empty, uses the latest available version.
	Version string

	// AutoUpdate enables automatic version checking and updating.
	// Default: true.
	AutoUpdate bool

	// HTTPTimeout is the timeout for HTTP requests (GitHub API, downloads).
	// Default: 60 seconds.
	HTTPTimeout time.Duration

	// RulesDir overrides the embedded rules directory.
	// If empty, uses embedded rules.
	RulesDir string
}

// DefaultConfig returns the default scanner configuration.
func DefaultConfig() *Config {
	return &Config{
		CacheDir:    "",
		Version:     "",
		AutoUpdate:  true,
		HTTPTimeout: 60 * time.Second,
	}
}
