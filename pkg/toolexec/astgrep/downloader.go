package astgrep

import (
	"context"
	"fmt"
	"runtime"

	"github.com/vigolium/vigolium/pkg/toolexec"
)

const (
	binaryName = "ast-grep"
)

// Downloader handles downloading and caching the ast-grep binary.
// Thread-safe for concurrent access.
type Downloader struct {
	inner *toolexec.Downloader
}

// NewDownloader creates a new Downloader with the given configuration.
func NewDownloader(config *Config) (*Downloader, error) {
	if config == nil {
		config = DefaultConfig()
	}

	d, err := toolexec.NewDownloader(astGrepSpec(), toolexec.DownloadConfig{
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

// GetBinary returns the path to the ast-grep binary, downloading if necessary.
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

// astGrepSpec returns the ToolSpec for ast-grep.
func astGrepSpec() toolexec.ToolSpec {
	return toolexec.ToolSpec{
		Name:             binaryName,
		CacheSubdir:      "ast-grep",
		LatestReleaseURL: "https://api.github.com/repos/ast-grep/ast-grep/releases/latest",
		UserAgent:        "Vigolium/1.0",
		ArchiveFormat:    toolexec.ArchiveZIP,
		CheckPATH:        true,
		ResolveDownloadURL: toolexec.ResolveViaAssetLookup(
			"ast-grep/ast-grep",
			astGrepPlatform,
			func(osName, archName string) string {
				return fmt.Sprintf("app-%s-%s.zip", archName, osName)
			},
		),
	}
}

// astGrepPlatform maps Go runtime values to ast-grep's naming convention.
func astGrepPlatform() (osName, archName string, err error) {
	switch runtime.GOOS {
	case "darwin":
		switch runtime.GOARCH {
		case "amd64":
			return "apple-darwin", "x86_64", nil
		case "arm64":
			return "apple-darwin", "aarch64", nil
		default:
			return "", "", fmt.Errorf("%w: architecture %s on darwin", toolexec.ErrUnsupportedPlatform, runtime.GOARCH)
		}
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return "unknown-linux-gnu", "x86_64", nil
		case "arm64":
			return "unknown-linux-gnu", "aarch64", nil
		default:
			return "", "", fmt.Errorf("%w: architecture %s on linux", toolexec.ErrUnsupportedPlatform, runtime.GOARCH)
		}
	default:
		return "", "", fmt.Errorf("%w: OS %s", toolexec.ErrUnsupportedPlatform, runtime.GOOS)
	}
}
