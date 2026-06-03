// Package jsscan provides a JavaScript analysis scanner that extracts endpoints,
// secrets, and other security-relevant information from JavaScript files.
//
// jsscan wraps an embedded binary tool, providing automatic extraction,
// caching, and a clean Go API. The binary is embedded at build time and
// extracted on first use. Checksum validation ensures the cached binary
// is updated when a new version is embedded.
//
// # Quick Start
//
//	scanner, err := jsscan.NewScanner(jsscan.DefaultConfig())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	result, err := scanner.Scan(ctx, jsContent)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, req := range result.Requests {
//	    fmt.Printf("Request: %s %s\n", req.Method, req.URL)
//	}
//
// # Binary Caching
//
// The jsscan binary is cached at ~/.cache/jsscan/ by default.
// The cache includes the binary and a checksum file. If the embedded
// binary's checksum differs from the cached version, the cache is
// automatically updated.
//
// # Thread Safety
//
// Both Scanner and Extractor are thread-safe for concurrent use.
// Multiple goroutines can safely call Scan() concurrently.
package jsscan

import (
	"errors"
	"time"
)

const (
	// MaxScanTimeout is the maximum timeout for a single scan operation.
	MaxScanTimeout = 5 * time.Minute
)

// Common errors for the jsscan package.
var (
	// ErrBinaryNotFound indicates the jsscan binary could not be extracted.
	ErrBinaryNotFound = errors.New("jsscan binary not found")

	// ErrExtractionFailed indicates binary extraction to cache failed.
	ErrExtractionFailed = errors.New("failed to extract jsscan binary")

	// ErrScanFailed indicates the jsscan scan command failed.
	ErrScanFailed = errors.New("jsscan scan failed")

	// ErrUnsupportedPlatform indicates the current OS/arch is not supported.
	ErrUnsupportedPlatform = errors.New("unsupported platform for jsscan")
)

// ExtractedRequest represents an HTTP request extracted from JavaScript.
type ExtractedRequest struct {
	URL     string   `json:"url"`
	Method  string   `json:"method"`
	Params  string   `json:"params"`
	Body    string   `json:"body"`
	Headers []string `json:"headers"`
	Cookies []string `json:"cookies"`
}

// CodeRecord represents extracted/transformed JavaScript code.
type CodeRecord struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// DomFlow is a DOM-XSS source→sink taint flow reported by jsscan. Unlike a
// "source and sink both present" heuristic, each DomFlow means the analyzer
// traced the same data from a DOM-controlled source into a dangerous sink.
type DomFlow struct {
	Source  string `json:"source"`
	Sink    string `json:"sink"`
	Snippet string `json:"snippet"`
	Line    int    `json:"line"`
}

// ScanResult contains the complete output from a jsscan analysis.
type ScanResult struct {
	Requests     []ExtractedRequest `json:"requests"`
	Code         *CodeRecord        `json:"code,omitempty"`
	DomFlows     []DomFlow          `json:"dom_flows,omitempty"`
	ScanDuration time.Duration      `json:"scan_duration"`
	BytesScanned int                `json:"bytes_scanned"`
}

// HasRequests returns true if any requests were extracted.
func (r *ScanResult) HasRequests() bool {
	return len(r.Requests) > 0
}

// HasCode returns true if code was extracted.
func (r *ScanResult) HasCode() bool {
	return r.Code != nil
}

// HasDomFlows returns true if any DOM-XSS taint flows were reported.
func (r *ScanResult) HasDomFlows() bool {
	return len(r.DomFlows) > 0
}

// Config configures the jsscan scanner behavior.
type Config struct {
	// CacheDir overrides the default cache directory (~/.cache/jsscan/).
	// If empty, uses the default location.
	CacheDir string
}

// DefaultConfig returns the default scanner configuration.
func DefaultConfig() *Config {
	return &Config{
		CacheDir: "",
	}
}

// CachedBinary holds information about a cached jsscan binary.
type CachedBinary struct {
	Path        string
	Checksum    string
	ExtractedAt time.Time
}
