package toolexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveCacheDir returns the cache directory path, using the override if set,
// otherwise falling back to os.UserCacheDir / ~/.cache.
func ResolveCacheDir(override, subdir string) (string, error) {
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

	return filepath.Join(cacheBase, subdir), nil
}

// IsBinaryValid checks if a binary file exists and is executable.
func IsBinaryValid(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && (info.Mode().Perm()&0111) != 0
}

// SplitLines splits a string into non-empty trimmed lines.
func SplitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
