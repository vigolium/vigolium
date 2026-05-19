package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const runPIDFile = "run.pid"

// RunPID holds process lifecycle metadata written to session directories.
// Used for orphan detection: if vigolium crashes, the next startup can find
// and kill orphaned agent subprocesses by scanning for stale PID files.
type RunPID struct {
	PID       int       `json:"pid"`
	PGID      int       `json:"pgid"`
	StartTime time.Time `json:"start_time"`
}

// WriteRunPID writes a run.pid JSON file to the given session directory.
func WriteRunPID(sessionDir string) error {
	if sessionDir == "" {
		return nil
	}
	pid := os.Getpid()
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		pgid = pid
	}
	info := RunPID{
		PID:       pid,
		PGID:      pgid,
		StartTime: time.Now(),
	}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sessionDir, runPIDFile), data, 0o644)
}

// RemoveRunPID removes the run.pid file from the session directory.
// Best-effort: errors are logged but not returned.
func RemoveRunPID(sessionDir string) {
	if sessionDir == "" {
		return
	}
	path := filepath.Join(sessionDir, runPIDFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		zap.L().Debug("Failed to remove PID file", zap.String("path", path), zap.Error(err))
	}
}

// ReadRunPID reads and parses a run.pid file. Returns nil if not found or invalid.
func ReadRunPID(pidPath string) *RunPID {
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return nil
	}
	var info RunPID
	if err := json.Unmarshal(data, &info); err != nil {
		return nil
	}
	return &info
}

// IsProcessAlive checks whether a process with the given PID is still running.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
