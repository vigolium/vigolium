package toolexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const versionFileName = "version.txt"

// Downloader handles downloading and caching a tool binary.
// Thread-safe for concurrent access.
type Downloader struct {
	mu         sync.RWMutex
	spec       ToolSpec
	config     DownloadConfig
	httpClient *http.Client
	cacheDir   string
	cached     *CachedBinary
}

// NewDownloader creates a Downloader for the given tool spec and config.
func NewDownloader(spec ToolSpec, config DownloadConfig) (*Downloader, error) {
	cacheDir, err := ResolveCacheDir(config.CacheDir, spec.CacheSubdir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache dir: %w", err)
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache dir %s: %w", cacheDir, err)
	}

	timeout := config.HTTPTimeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &Downloader{
		spec:   spec,
		config: config,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		cacheDir: cacheDir,
	}, nil
}

// GetBinary returns the path to the tool binary, downloading if necessary.
// Uses double-check locking for thread safety with lazy initialization.
//
// Resolution order:
//  1. In-memory cache
//  2. System PATH (if spec.CheckPATH is true)
//  3. On-disk cache
//  4. GitHub release download
func (d *Downloader) GetBinary(ctx context.Context) (*CachedBinary, error) {
	// Fast path: read lock
	d.mu.RLock()
	if d.cached != nil && IsBinaryValid(d.cached.Path) {
		cached := d.cached
		d.mu.RUnlock()
		return cached, nil
	}
	d.mu.RUnlock()

	// Slow path: write lock
	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-check after acquiring write lock
	if d.cached != nil && IsBinaryValid(d.cached.Path) {
		return d.cached, nil
	}

	// Check system PATH
	if d.spec.CheckPATH {
		if systemPath, err := exec.LookPath(d.spec.Name); err == nil {
			d.cached = &CachedBinary{
				Path:         systemPath,
				Version:      "system",
				DownloadedAt: time.Now(),
			}
			return d.cached, nil
		}
	}

	// Try disk cache
	cached, err := d.loadFromDisk()
	if err == nil && cached != nil {
		if d.config.AutoUpdate {
			latest, checkErr := d.checkLatestVersion(ctx)
			if checkErr == nil && latest != cached.Version {
				cached, err = d.downloadAndCache(ctx, latest)
				if err != nil {
					cached, _ = d.loadFromDisk()
				}
			}
		}
		if cached != nil {
			d.cached = cached
			return cached, nil
		}
	}

	// Must download
	version := d.config.Version
	if version == "" {
		version, err = d.checkLatestVersion(ctx)
		if err != nil {
			return nil, fmt.Errorf("check latest version: %w", err)
		}
	}

	cached, err = d.downloadAndCache(ctx, version)
	if err != nil {
		return nil, err
	}

	d.cached = cached
	return cached, nil
}

// checkLatestVersion queries GitHub API for the latest release version.
func (d *Downloader) checkLatestVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.spec.LatestReleaseURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", d.spec.UserAgent)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch release info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("decode release info: %w", err)
	}

	return release.TagName, nil
}

// downloadAndCache downloads the binary and caches it to disk.
func (d *Downloader) downloadAndCache(ctx context.Context, version string) (*CachedBinary, error) {
	downloadURL, err := d.spec.ResolveDownloadURL(ctx, d, version)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	req.Header.Set("User-Agent", d.spec.UserAgent)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %d from %s", ErrDownloadFailed, resp.StatusCode, downloadURL)
	}

	maxSize := d.spec.maxBinarySizeOrDefault()
	binaryPath := filepath.Join(d.cacheDir, d.spec.Name)

	// Read the archive into memory (bounded by maxSize) so we can verify its
	// checksum before trusting any bytes. maxSize+1 lets us detect overflow.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrDownloadFailed, err)
	}
	if int64(len(body)) > maxSize {
		return nil, fmt.Errorf("%w: archive exceeds max size %d bytes", ErrDownloadFailed, maxSize)
	}

	if err := d.verifyChecksum(ctx, version, body); err != nil {
		return nil, err
	}

	switch d.spec.ArchiveFormat {
	case ArchiveZIP:
		if err := extractFromZIP(body, d.spec.Name, binaryPath, maxSize); err != nil {
			return nil, err
		}
	case ArchiveTGZ:
		if err := extractFromTGZ(bytes.NewReader(body), d.spec.Name, binaryPath, maxSize); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported archive format: %d", d.spec.ArchiveFormat)
	}

	if err := os.Chmod(binaryPath, 0755); err != nil {
		return nil, fmt.Errorf("chmod binary: %w", err)
	}

	// Write version file
	versionPath := filepath.Join(d.cacheDir, versionFileName)
	versionData := fmt.Sprintf("%s\n%s", version, time.Now().Format(time.RFC3339))
	if err := os.WriteFile(versionPath, []byte(versionData), 0644); err != nil {
		return nil, fmt.Errorf("write version file: %w", err)
	}

	return &CachedBinary{
		Path:         binaryPath,
		Version:      version,
		DownloadedAt: time.Now(),
	}, nil
}

// verifyChecksum checks the downloaded archive bytes against the expected
// SHA-256 from spec.ResolveChecksum. It is a no-op when no resolver is set or
// the resolver returns an empty digest (tools without published checksums).
func (d *Downloader) verifyChecksum(ctx context.Context, version string, archive []byte) error {
	if d.spec.ResolveChecksum == nil {
		return nil
	}
	expected, err := d.spec.ResolveChecksum(ctx, d, version)
	if err != nil {
		return fmt.Errorf("%w: resolve expected checksum: %v", ErrChecksumMismatch, err)
	}
	expected = strings.ToLower(strings.TrimSpace(expected))
	if expected == "" {
		return nil
	}
	sum := sha256.Sum256(archive)
	got := hex.EncodeToString(sum[:])
	if got != expected {
		return fmt.Errorf("%w: %s expected sha256 %s, got %s", ErrChecksumMismatch, d.spec.Name, expected, got)
	}
	return nil
}

// loadFromDisk attempts to load cached binary info from disk.
func (d *Downloader) loadFromDisk() (*CachedBinary, error) {
	binaryPath := filepath.Join(d.cacheDir, d.spec.Name)
	versionPath := filepath.Join(d.cacheDir, versionFileName)

	if !IsBinaryValid(binaryPath) {
		return nil, fmt.Errorf("binary not found or invalid")
	}

	data, err := os.ReadFile(versionPath)
	if err != nil {
		return nil, fmt.Errorf("read version file: %w", err)
	}

	lines := SplitLines(string(data))
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid version file format")
	}

	downloadedAt, err := time.Parse(time.RFC3339, lines[1])
	if err != nil {
		downloadedAt = time.Now()
	}

	return &CachedBinary{
		Path:         binaryPath,
		Version:      lines[0],
		DownloadedAt: downloadedAt,
	}, nil
}

// CacheDir returns the resolved cache directory path.
func (d *Downloader) CacheDir() string {
	return d.cacheDir
}

// Clear removes the cached binary and version file.
func (d *Downloader) Clear() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cached = nil

	_ = os.Remove(filepath.Join(d.cacheDir, d.spec.Name))
	_ = os.Remove(filepath.Join(d.cacheDir, versionFileName))

	return nil
}

// HTTPClient returns the downloader's HTTP client, useful for
// ResolveDownloadURL functions that need to make additional API calls.
func (d *Downloader) HTTPClient() *http.Client {
	return d.httpClient
}
