package wordlists

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultPaths holds on-disk paths to the materialized embedded default wordlists.
// A field is empty only if that list could not be written.
type DefaultPaths struct {
	ShortFile string
	LongFile  string
	ShortDir  string
	LongDir   string
	Fuzz      string
}

// EnsureOnDisk materializes the embedded default wordlists into dir (created if
// absent) and returns their on-disk paths. deparos loads wordlists from file
// paths only — it has no in-memory provider for the built-in list types (see
// pkg/deparos/discovery/payload/wordlist_cache.go, which os.Open's the path) —
// so the embedded lists must be written out before they can serve as defaults.
// Each file is (re)written only when missing or size-mismatched, and writes are
// atomic (temp + rename) so a concurrent scan never observes a partial file.
func EnsureOnDisk(dir string) (DefaultPaths, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DefaultPaths{}, fmt.Errorf("create wordlist dir %s: %w", dir, err)
	}

	var paths DefaultPaths
	targets := []struct {
		name string
		dst  *string
	}{
		{"file-short.txt", &paths.ShortFile},
		{"file-long.txt", &paths.LongFile},
		{"dir-short.txt", &paths.ShortDir},
		{"dir-long.txt", &paths.LongDir},
		{"fuzz.txt", &paths.Fuzz},
	}
	for _, t := range targets {
		p, err := materialize(dir, t.name)
		if err != nil {
			return paths, err
		}
		*t.dst = p
	}
	return paths, nil
}

// materialize writes a single embedded wordlist into dir, returning its path.
// It skips the write when an up-to-date copy (same size) is already present.
func materialize(dir, name string) (string, error) {
	data, err := WordlistsFS.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("read embedded wordlist %s: %w", name, err)
	}

	dst := filepath.Join(dir, name)
	if info, statErr := os.Stat(dst); statErr == nil && info.Mode().IsRegular() && info.Size() == int64(len(data)) {
		return dst, nil // already current
	}

	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", fmt.Errorf("write wordlist %s: %w", name, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("install wordlist %s: %w", name, err)
	}
	return dst, nil
}
