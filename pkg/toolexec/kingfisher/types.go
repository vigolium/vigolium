// Package kingfisher provides a MongoDB security scanner that detects exposed credentials.
//
// Kingfisher wraps the MongoDB kingfisher binary tool, providing automatic
// downloading, caching, and a clean Go API. The binary is downloaded from
// GitHub releases on first use and cached for subsequent scans.
//
// # Quick Start
//
// The simplest way to use kingfisher is with the package-level Scan function:
//
//	result, err := kingfisher.Scan(ctx, responseBody)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, finding := range result.Findings {
//	    fmt.Printf("%s: %s\n", finding.Severity, finding.Description)
//	}
//
// # Custom Configuration
//
// For more control, create a Scanner with custom configuration:
//
//	config := &kingfisher.Config{
//	    ScanTimeout: 60 * time.Second,
//	    AutoUpdate:  false,
//	    Version:     "v1.71.0",
//	}
//	scanner, err := kingfisher.NewScanner(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result, err := scanner.Scan(ctx, body)
//
// # Binary Caching
//
// The kingfisher binary is cached at ~/.cache/kingfisher/ by default.
// The cache includes the binary and a version file. When AutoUpdate is
// enabled (default), the scanner checks GitHub for newer versions and
// updates automatically.
//
// # Thread Safety
//
// Both Scanner and Downloader are thread-safe for concurrent use.
// Multiple goroutines can safely call Scan() concurrently.
package kingfisher

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

	// ErrScanFailed indicates the kingfisher scan command failed.
	ErrScanFailed = errors.New("kingfisher scan failed")
)

// Finding represents a single credential or security issue discovered by kingfisher.
// JSON format from kingfisher:
//
//	{"rule":{"name":"MongoDB URI Connection String","id":"kingfisher.mongodb.3"},
//	 "finding":{"snippet":"mongodb://...", "fingerprint":"...", "confidence":"medium",
//	            "entropy":"4.43", "validation":{"status":"Not Attempted"}, "line":1}}
type Finding struct {
	Rule    RuleInfo    `json:"rule"`
	Finding FindingInfo `json:"finding"`
}

// RuleInfo contains the rule that triggered the finding.
type RuleInfo struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// FindingInfo contains the actual finding details.
type FindingInfo struct {
	Snippet     string         `json:"snippet"`
	Fingerprint string         `json:"fingerprint"`
	Confidence  string         `json:"confidence"`
	Entropy     string         `json:"entropy"`
	Validation  ValidationInfo `json:"validation"`
	Language    string         `json:"language"`
	Line        int            `json:"line"`
	ColumnStart int            `json:"column_start"`
	ColumnEnd   int            `json:"column_end"`
	Path        string         `json:"path"`
}

// ValidationInfo contains secret validation status.
type ValidationInfo struct {
	Status   string `json:"status"`
	Response string `json:"response,omitempty"`
}

// RuleName returns the rule name that triggered this finding.
func (f *Finding) RuleName() string {
	return f.Rule.Name
}

// RuleID returns the rule ID.
func (f *Finding) RuleID() string {
	return f.Rule.ID
}

// Snippet returns the matched secret snippet.
func (f *Finding) Snippet() string {
	return f.Finding.Snippet
}

// IsValidated returns true if the secret was validated as active.
func (f *Finding) IsValidated() bool {
	return f.Finding.Validation.Status == "Verified"
}

// ScanResult contains the complete output from a kingfisher scan.
type ScanResult struct {
	// Findings is the list of discovered security issues.
	Findings []Finding `json:"findings"`

	// ScanDuration is how long the scan took.
	ScanDuration time.Duration `json:"scan_duration"`

	// BytesScanned is the size of input that was scanned.
	BytesScanned int `json:"bytes_scanned"`
}

// HasFindings returns true if any findings were discovered.
func (r *ScanResult) HasFindings() bool {
	return len(r.Findings) > 0
}

// VerifiedFindings returns only findings that were verified as active.
func (r *ScanResult) VerifiedFindings() []Finding {
	var verified []Finding
	for _, f := range r.Findings {
		if f.IsValidated() {
			verified = append(verified, f)
		}
	}
	return verified
}

// Config configures the kingfisher scanner behavior.
type Config struct {
	// CacheDir overrides the default cache directory (~/.cache/kingfisher/).
	// If empty, uses the default location.
	CacheDir string

	// Version specifies a specific kingfisher version to use.
	// If empty, uses the latest available version.
	Version string

	// AutoUpdate enables automatic version checking and updating.
	// Default: true.
	AutoUpdate bool

	// HTTPTimeout is the timeout for HTTP requests (GitHub API, downloads).
	// Default: 60 seconds.
	HTTPTimeout time.Duration
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
