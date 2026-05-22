package toolexec

import "context"

// ArchiveFormat identifies the archive type used by a tool's releases.
type ArchiveFormat int

const (
	ArchiveZIP ArchiveFormat = iota
	ArchiveTGZ
)

// ToolSpec parameterizes the Downloader for a specific external tool.
// Consumer packages create a spec and pass it to NewDownloader.
type ToolSpec struct {
	// Name is the binary name on disk (e.g., "kingfisher").
	Name string

	// CacheSubdir is the subdirectory under the user cache dir
	// (e.g., "kingfisher").
	CacheSubdir string

	// LatestReleaseURL is the GitHub API URL for fetching the latest release.
	LatestReleaseURL string

	// UserAgent is sent with HTTP requests.
	UserAgent string

	// ArchiveFormat is ZIP or TGZ.
	ArchiveFormat ArchiveFormat

	// CheckPATH controls whether exec.LookPath is tried before downloading.
	CheckPATH bool

	// ResolveDownloadURL returns the download URL for the given version.
	// The Downloader is passed so the function can use its HTTP client.
	ResolveDownloadURL func(ctx context.Context, d *Downloader, version string) (string, error)

	// ResolveChecksum optionally returns the expected lowercase hex SHA-256 of
	// the downloaded archive asset for the given version. When non-nil and it
	// returns a non-empty digest, the downloader verifies the archive bytes
	// before extraction and rejects a mismatch (ErrChecksumMismatch). Leave nil
	// for tools whose releases do not publish checksums — TLS to the release
	// host is then the only integrity guarantee. Use ResolveChecksumViaTemplate
	// for releases that publish a sidecar checksum file.
	ResolveChecksum func(ctx context.Context, d *Downloader, version string) (string, error)

	// MaxBinarySize is the maximum allowed binary size in bytes.
	// Defaults to 100MB if zero.
	MaxBinarySize int64
}

// maxBinarySizeOrDefault returns the configured max size or the default.
func (s *ToolSpec) maxBinarySizeOrDefault() int64 {
	if s.MaxBinarySize > 0 {
		return s.MaxBinarySize
	}
	return 100 * 1024 * 1024 // 100MB
}
