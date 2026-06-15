package agent

import (
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/pkg/procutil"
	"go.uber.org/zap"
)

// CleanupOrphanedProcesses scans session directories for run.pid files and
// cleans up orphaned agent processes. For dead processes, it removes the stale
// PID file. For alive orphans, it sends SIGTERM then SIGKILL to the process group.
// Returns the number of sessions cleaned up.
func CleanupOrphanedProcesses(sessionsDir string) int {
	if sessionsDir == "" {
		return 0
	}
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return 0
	}

	cleaned := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidPath := filepath.Join(sessionsDir, entry.Name(), runPIDFile)
		info := ReadRunPID(pidPath)
		if info == nil {
			continue
		}

		if !IsProcessAlive(info.PID) {
			// Process is dead — just remove the stale PID file.
			_ = os.Remove(pidPath)
			cleaned++
			zap.L().Debug("Removed stale PID file (process dead)",
				zap.String("session", entry.Name()),
				zap.Int("pid", info.PID))
			continue
		}

		// Process is alive but orphaned — kill the process group.
		zap.L().Info("Killing orphaned agent process",
			zap.String("session", entry.Name()),
			zap.Int("pgid", info.PGID))

		if err := killProcessGroup(info.PGID); err != nil {
			zap.L().Debug("Failed to kill orphaned process group",
				zap.Int("pgid", info.PGID), zap.Error(err))
		}
		_ = os.Remove(pidPath)
		cleaned++
	}
	return cleaned
}

// killProcessGroup sends SIGTERM to a process group, waits up to 3 seconds,
// then escalates to SIGKILL. The platform-specific signaling lives in
// procutil (procgroup_unix.go, procgroup_windows.go).
func killProcessGroup(pgid int) error {
	if pgid <= 0 {
		return nil
	}
	if err := procutil.SignalProcessGroup(pgid, false); err != nil { // SIGTERM (graceful)
		return err
	}

	// Wait up to 3 seconds for exit.
	for i := 0; i < 6; i++ {
		time.Sleep(500 * time.Millisecond)
		if !procutil.IsProcessGroupAlive(pgid) {
			return nil
		}
	}

	// Escalate to SIGKILL.
	_ = procutil.SignalProcessGroup(pgid, true)
	return nil
}

// CleanupStaleTempDirs removes orphaned vigolium temp directories older than 24 hours.
func CleanupStaleTempDirs() {
	pattern := filepath.Join(os.TempDir(), "vigolium-swarm-ext-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, dir := range matches {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.RemoveAll(dir); err == nil {
				zap.L().Debug("Removed stale temp dir", zap.String("path", dir))
			}
		}
	}
}
