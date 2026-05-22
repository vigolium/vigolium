package kingfisher

import (
	"context"
	"fmt"
	"runtime"

	"github.com/vigolium/vigolium/pkg/toolexec"
)

const (
	binaryName = "kingfisher"
)

// Downloader handles downloading and caching the kingfisher binary.
// Thread-safe for concurrent access.
type Downloader struct {
	inner *toolexec.Downloader
}

// NewDownloader creates a new Downloader with the given configuration.
func NewDownloader(config *Config) (*Downloader, error) {
	if config == nil {
		config = DefaultConfig()
	}

	d, err := toolexec.NewDownloader(kingfisherSpec(), toolexec.DownloadConfig{
		CacheDir:    config.CacheDir,
		Version:     config.Version,
		AutoUpdate:  config.AutoUpdate,
		HTTPTimeout: config.HTTPTimeout,
	})
	if err != nil {
		return nil, err
	}

	return &Downloader{inner: d}, nil
}

// GetBinary returns the path to the kingfisher binary, downloading if necessary.
func (d *Downloader) GetBinary(ctx context.Context) (*toolexec.CachedBinary, error) {
	return d.inner.GetBinary(ctx)
}

// CacheDir returns the resolved cache directory path.
func (d *Downloader) CacheDir() string {
	return d.inner.CacheDir()
}

// Clear removes the cached binary and version file.
func (d *Downloader) Clear() error {
	return d.inner.Clear()
}

// kingfisherSpec returns the ToolSpec for kingfisher.
func kingfisherSpec() toolexec.ToolSpec {
	return toolexec.ToolSpec{
		Name:             binaryName,
		CacheSubdir:      "kingfisher",
		LatestReleaseURL: "https://api.github.com/repos/mongodb/kingfisher/releases/latest",
		UserAgent:        "Deparos/1.0",
		ArchiveFormat:    toolexec.ArchiveTGZ,
		CheckPATH:        false,
		ResolveDownloadURL: toolexec.ResolveViaTemplate(
			"https://github.com/mongodb/kingfisher/releases/download/%s/kingfisher-%s-%s.tgz",
			kingfisherPlatform,
		),
		// mongodb/kingfisher releases do not publish per-asset checksum files, so
		// ResolveChecksum is left nil — integrity rests on TLS to github.com. If
		// upstream starts shipping "<asset>.sha256" sidecars, wire it with
		// toolexec.ResolveChecksumViaTemplate to enable verification.
	}
}

// kingfisherPlatform maps Go runtime values to kingfisher's naming convention.
func kingfisherPlatform() (osName, archName string, err error) {
	switch runtime.GOOS {
	case "darwin":
		osName = "darwin"
	case "linux":
		osName = "linux"
	default:
		return "", "", fmt.Errorf("%w: OS %s", toolexec.ErrUnsupportedPlatform, runtime.GOOS)
	}

	switch runtime.GOARCH {
	case "amd64":
		archName = "x64"
	case "arm64":
		archName = "arm64"
	default:
		return "", "", fmt.Errorf("%w: architecture %s", toolexec.ErrUnsupportedPlatform, runtime.GOARCH)
	}

	return osName, archName, nil
}
