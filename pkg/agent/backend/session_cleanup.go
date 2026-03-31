package backend

import (
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// CleanupSessionDirs removes session directories under sessionsDir that are
// older than maxAge. It returns the number of directories deleted.
func CleanupSessionDirs(sessionsDir string, maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-maxAge)
	deleted := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			zap.L().Debug("Failed to stat session dir entry", zap.String("name", entry.Name()), zap.Error(err))
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(sessionsDir, entry.Name())
			if err := os.RemoveAll(path); err != nil {
				zap.L().Debug("Failed to remove old session dir", zap.String("path", path), zap.Error(err))
				continue
			}
			deleted++
		}
	}

	return deleted, nil
}
