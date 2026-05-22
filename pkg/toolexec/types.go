// Package toolexec provides unified binary downloading, caching, and command
// execution for external CLI tools (e.g., kingfisher).
//
// It extracts two patterns that were duplicated across consumer packages:
//   - GitHub release downloading with disk caching, version management,
//     and double-check locking (Downloader).
//   - exec.CommandContext execution with stdout/stderr capture and
//     tolerance for non-zero exit codes when stdout has data (Run).
//
// Consumer packages define a ToolSpec that parameterizes the differences
// (archive format, platform naming, URL resolution strategy) and delegate
// to toolexec for the heavy lifting.
package toolexec

import (
	"errors"
	"time"
)

// Sentinel errors shared across all tool downloaders.
var (
	ErrBinaryNotFound      = errors.New("binary not found")
	ErrDownloadFailed      = errors.New("failed to download binary")
	ErrExtractionFailed    = errors.New("failed to extract binary")
	ErrUnsupportedPlatform = errors.New("unsupported platform")
	ErrChecksumMismatch    = errors.New("downloaded archive failed checksum verification")
)

// CachedBinary holds information about a cached tool binary.
type CachedBinary struct {
	// Path is the absolute path to the binary.
	Path string

	// Version is the version string (e.g., "0.25.0", "v1.71.0").
	Version string

	// DownloadedAt is when the binary was downloaded.
	DownloadedAt time.Time
}

// DownloadConfig contains shared configuration for binary downloading.
type DownloadConfig struct {
	// CacheDir overrides the default cache directory.
	// If empty, uses ~/.cache/<tool-name>/.
	CacheDir string

	// Version specifies a specific version to use.
	// If empty, uses the latest available version.
	Version string

	// AutoUpdate enables automatic version checking and updating.
	AutoUpdate bool

	// HTTPTimeout is the timeout for HTTP requests (GitHub API, downloads).
	HTTPTimeout time.Duration
}

// DefaultDownloadConfig returns sensible defaults.
func DefaultDownloadConfig() DownloadConfig {
	return DownloadConfig{
		AutoUpdate:  true,
		HTTPTimeout: 60 * time.Second,
	}
}

// GitHubRelease represents the GitHub API response for a release.
type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []GitHubAsset `json:"assets"`
}

// GitHubAsset represents a single downloadable asset from a GitHub release.
type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ExecResult holds the output from a command execution.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}
