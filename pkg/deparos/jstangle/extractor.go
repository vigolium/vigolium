package jstangle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCacheSubdir is the subdirectory under user cache for jstangle.
	DefaultCacheSubdir = "jstangle"

	// ChecksumFileName stores the cached checksum info.
	ChecksumFileName = "checksum.txt"
)

var (
	embeddedChecksum     string
	embeddedChecksumOnce sync.Once
)

// getEmbeddedChecksum calculates SHA256 of embeddedBinary once at runtime.
// No hardcoded checksum needed - automatically updates when binary changes.
func getEmbeddedChecksum() string {
	embeddedChecksumOnce.Do(func() {
		hash := sha256.Sum256(embeddedBinary)
		embeddedChecksum = hex.EncodeToString(hash[:])
	})
	return embeddedChecksum
}

// Extractor handles extracting and caching the jstangle binary.
// Thread-safe for concurrent access.
type Extractor struct {
	mu       sync.RWMutex
	config   *Config
	cacheDir string
	cached   *CachedBinary
}

// NewExtractor creates a new Extractor with the given configuration.
// It initializes the cache directory but does not extract the binary yet (lazy loading).
func NewExtractor(config *Config) (*Extractor, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if !isEmbeddedBinaryValid() {
		return nil, ErrUnsupportedPlatform
	}

	cacheDir, err := resolveCacheDir(config.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache dir: %w", err)
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache dir %s: %w", cacheDir, err)
	}

	return &Extractor{
		config:   config,
		cacheDir: cacheDir,
	}, nil
}

// resolveCacheDir returns the cache directory path.
// Uses ~/.cache/jstangle/ by default.
func resolveCacheDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}

	cacheBase, err := os.UserCacheDir()
	if err != nil {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get user home dir: %w", err)
		}
		cacheBase = filepath.Join(home, ".cache")
	}

	return filepath.Join(cacheBase, DefaultCacheSubdir), nil
}

// GetBinary returns the path to the jstangle binary, extracting if necessary.
// Uses double-check locking for thread safety with lazy initialization.
func (e *Extractor) GetBinary() (*CachedBinary, error) {
	e.mu.RLock()
	if e.cached != nil && e.isBinaryValid(e.cached.Path) && e.isChecksumCurrent(e.cached.Checksum) {
		cached := e.cached
		e.mu.RUnlock()
		return cached, nil
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cached != nil && e.isBinaryValid(e.cached.Path) && e.isChecksumCurrent(e.cached.Checksum) {
		return e.cached, nil
	}

	cached, err := e.loadFromDisk()
	if err == nil && cached != nil && e.isChecksumCurrent(cached.Checksum) {
		e.cached = cached
		return cached, nil
	}

	cached, err = e.extractAndCache()
	if err != nil {
		return nil, err
	}

	e.cached = cached
	return cached, nil
}

// isChecksumCurrent checks if the given checksum matches the embedded binary checksum.
func (e *Extractor) isChecksumCurrent(checksum string) bool {
	return checksum == getEmbeddedChecksum()
}

// extractAndCache extracts the embedded binary to the cache directory.
func (e *Extractor) extractAndCache() (*CachedBinary, error) {
	binaryPath := filepath.Join(e.cacheDir, binaryName)

	if err := os.WriteFile(binaryPath, embeddedBinary, 0755); err != nil {
		return nil, fmt.Errorf("%w: write binary: %w", ErrExtractionFailed, err)
	}

	currentChecksum := getEmbeddedChecksum()

	checksumPath := filepath.Join(e.cacheDir, ChecksumFileName)
	checksumData := fmt.Sprintf("%s\n%s", currentChecksum, time.Now().Format(time.RFC3339))
	if err := os.WriteFile(checksumPath, []byte(checksumData), 0644); err != nil {
		return nil, fmt.Errorf("write checksum file: %w", err)
	}

	return &CachedBinary{
		Path:        binaryPath,
		Checksum:    currentChecksum,
		ExtractedAt: time.Now(),
	}, nil
}

// loadFromDisk attempts to load cached binary info from disk.
func (e *Extractor) loadFromDisk() (*CachedBinary, error) {
	binaryPath := filepath.Join(e.cacheDir, binaryName)
	checksumPath := filepath.Join(e.cacheDir, ChecksumFileName)

	if !e.isBinaryValid(binaryPath) {
		return nil, fmt.Errorf("binary not found or invalid")
	}

	data, err := os.ReadFile(checksumPath)
	if err != nil {
		return nil, fmt.Errorf("read checksum file: %w", err)
	}

	lines := splitLines(string(data))
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid checksum file format")
	}

	extractedAt, err := time.Parse(time.RFC3339, lines[1])
	if err != nil {
		extractedAt = time.Now()
	}

	return &CachedBinary{
		Path:        binaryPath,
		Checksum:    lines[0],
		ExtractedAt: extractedAt,
	}, nil
}

// isBinaryValid checks if a binary file exists and is executable.
func (e *Extractor) isBinaryValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && (info.Mode().Perm()&0111) != 0
}

// splitLines splits a string into lines, trimming whitespace.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// CacheDir returns the resolved cache directory path.
func (e *Extractor) CacheDir() string {
	return e.cacheDir
}

// Clear removes the cached binary and checksum file.
func (e *Extractor) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.cached = nil

	binaryPath := filepath.Join(e.cacheDir, binaryName)
	checksumPath := filepath.Join(e.cacheDir, ChecksumFileName)

	_ = os.Remove(binaryPath)
	_ = os.Remove(checksumPath)

	return nil
}
