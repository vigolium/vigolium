package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// pioliumAuthFileName is the cred file pi's codex provider reads. Lives
// inside PI_CODING_AGENT_DIR (the same directory vigolium points pi at via
// piolium.RuntimeEnv) — for a system install at /opt/piolium that's
// /opt/piolium/agent/auth.json; for a user install pinned with
// $PIOLIUM_HOME=~/.piolium that's ~/.piolium/agent/auth.json.
const pioliumAuthFileName = "auth.json"

// pioliumAuthBackupPrefix is the prefix attached to a moved-aside auth.json
// during a BYOK staging operation. The full backup name is
// `auth.json.vigolium-bak-<runUUID>` so two concurrent runs (each locked
// separately) cannot stomp each other's backups.
const pioliumAuthBackupPrefix = pioliumAuthFileName + ".vigolium-bak-"

// pioliumAuthLockFileName protects against two concurrent BYOK audit runs
// racing on the same auth.json swap. The first run wins; the second
// returns a clean error rather than letting the two interleave.
const pioliumAuthLockFileName = ".vigolium-auth.lock"

// pioliumLockBreadcrumb is the JSON written to .vigolium-auth.lock so a
// later sweep (or operator) can identify the holder. Kept compatible with
// the vigolium-audit lock breadcrumb shape (engine/auth-overrides.ts) so a
// single tool can parse either.
type pioliumLockBreadcrumb struct {
	Run        string `json:"run"`
	PID        int    `json:"pid"`
	StartedAt  string `json:"started_at"`
	CredTarget string `json:"cred_target"`
}

// stagePioliumCodexCred copies the user-supplied codex cred file into
// pi's auth.json location for the duration of one audit run, with
// backup-and-restore + a per-dir lock against concurrent BYOK runs.
//
// Behavior:
//   - Acquires an exclusive lock at <piAgentDir>/.vigolium-auth.lock.
//     Returns a clear error on contention so the operator sees a
//     descriptive failure instead of two runs trampling each other's
//     auth.json.
//   - If <piAgentDir>/auth.json exists, renames it to
//     auth.json.vigolium-bak-<runUUID> for restore.
//   - Copies credSrc → <piAgentDir>/auth.json (mode 0600).
//   - Returns a cleanup func that the caller MUST defer. Cleanup deletes
//     the staged file, restores the backup (if any), and releases the
//     lock. Idempotent: callers that invoke it twice get the same end
//     state, no error.
//
// Returns (nil, nil) when piAgentDir is empty (no system piolium install
// detected) — the caller can fall back to whatever pi resolves on its own
// (~/.codex/auth.json, $OPENAI_API_KEY, etc.) and the operator gets a
// best-effort run rather than a hard fail. We still log the situation so
// it's visible.
func stagePioliumCodexCred(credSrc, piAgentDir, runUUID string) (cleanup func(), err error) {
	piAgentDir = strings.TrimSpace(piAgentDir)
	credSrc = strings.TrimSpace(credSrc)
	if piAgentDir == "" {
		zap.L().Warn("piolium codex BYOK: PI_CODING_AGENT_DIR not resolvable, skipping auth.json staging — pi will fall back to its own resolution",
			zap.String("cred_src", credSrc))
		return func() {}, nil
	}
	if credSrc == "" {
		return func() {}, nil
	}

	if info, statErr := os.Stat(credSrc); statErr != nil {
		return nil, fmt.Errorf("piolium codex BYOK: read cred file %s: %w", credSrc, statErr)
	} else if info.IsDir() {
		return nil, fmt.Errorf("piolium codex BYOK: cred file %s is a directory", credSrc)
	}

	if mkErr := os.MkdirAll(piAgentDir, 0o755); mkErr != nil {
		return nil, fmt.Errorf("piolium codex BYOK: ensure %s: %w", piAgentDir, mkErr)
	}

	lockPath := filepath.Join(piAgentDir, pioliumAuthLockFileName)
	target := filepath.Join(piAgentDir, pioliumAuthFileName)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			holder := readPioliumLockBreadcrumb(lockPath)
			return nil, fmt.Errorf("piolium codex BYOK: another vigolium audit is staging %s (lock held by run=%s pid=%d started_at=%s) — wait for it to finish or remove %s if no audit is running",
				piAgentDir, holder.Run, holder.PID, holder.StartedAt, lockPath)
		}
		return nil, fmt.Errorf("piolium codex BYOK: acquire lock %s: %w", lockPath, err)
	}
	// JSON breadcrumb so SweepStaleAuthBackups can identify the holder and
	// decide whether to restore on a future boot. Kept on a single line so
	// reads are trivially atomic on POSIX filesystems.
	bc := pioliumLockBreadcrumb{
		Run:        runUUID,
		PID:        os.Getpid(),
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		CredTarget: target,
	}
	if blob, mErr := json.Marshal(bc); mErr == nil {
		_, _ = lockFile.Write(append(blob, '\n'))
	}
	_ = lockFile.Close()

	releaseLock := func() {
		if rmErr := os.Remove(lockPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			zap.L().Warn("piolium codex BYOK: failed to release lock",
				zap.String("path", lockPath), zap.Error(rmErr))
		}
	}

	// Rename-then-check rather than stat-then-rename: avoids a TOCTOU window
	// where another process could remove `target` between the stat and the
	// rename. ENOENT means "no prior file to back up" — backupPath stays
	// empty and we proceed straight to copying the override in.
	var backupPath string
	candidate := filepath.Join(piAgentDir, pioliumAuthBackupPrefix+runUUID)
	if rnErr := os.Rename(target, candidate); rnErr == nil {
		backupPath = candidate
	} else if !errors.Is(rnErr, os.ErrNotExist) {
		releaseLock()
		return nil, fmt.Errorf("piolium codex BYOK: backup existing %s → %s: %w", target, candidate, rnErr)
	}

	if copyErr := copyFileMode(credSrc, target, 0o600); copyErr != nil {
		// Restore backup before bailing so we don't leave the dir in a
		// half-staged state for the operator.
		if backupPath != "" {
			if rnErr := os.Rename(backupPath, target); rnErr != nil {
				zap.L().Warn("piolium codex BYOK: failed to restore backup after copy failure",
					zap.String("backup", backupPath), zap.String("target", target), zap.Error(rnErr))
			}
		}
		releaseLock()
		return nil, fmt.Errorf("piolium codex BYOK: stage %s → %s: %w", credSrc, target, copyErr)
	}

	zap.L().Debug("piolium codex BYOK: staged cred file",
		zap.String("cred_src", credSrc),
		zap.String("staged", target),
		zap.String("backup", backupPath),
		zap.String("run", runUUID))

	var once sync.Once
	cleanup = func() {
		once.Do(func() {
			defer releaseLock()
			if rmErr := os.Remove(target); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				zap.L().Warn("piolium codex BYOK: failed to remove staged cred file",
					zap.String("path", target), zap.Error(rmErr))
			}
			if backupPath != "" {
				if rnErr := os.Rename(backupPath, target); rnErr != nil {
					zap.L().Warn("piolium codex BYOK: failed to restore backup — operator must restore manually",
						zap.String("backup", backupPath), zap.String("target", target), zap.Error(rnErr))
				}
			}
		})
	}
	return cleanup, nil
}

// readPioliumLockBreadcrumb parses the JSON breadcrumb written by
// stagePioliumCodexCred. Returns a zero-valued breadcrumb when the file
// is unreadable or not JSON — callers rely on the literal "" / 0 values
// to format an "unknown holder" message.
func readPioliumLockBreadcrumb(path string) pioliumLockBreadcrumb {
	var out pioliumLockBreadcrumb
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out) // tolerant: zero values are fine
	return out
}

// PioliumSweepResult summarizes what SweepStalePioliumAuth did per agent
// directory. Returned so the caller can log a single structured line.
type PioliumSweepResult struct {
	Swept    []PioliumSweepEntry // backup → target restored, lock removed
	Held     []PioliumSweepEntry // active run holds the lock; left alone
	Orphaned []string            // backup files without a matching restore target
}

// PioliumSweepEntry captures one swept or held lock + backup pair.
type PioliumSweepEntry struct {
	Dir        string
	LockPath   string
	BackupPath string
	Holder     pioliumLockBreadcrumb
}

// SweepStalePioliumAuth restores credentials left orphaned by a crashed
// BYOK run. For each candidate piAgentDir:
//
//   - If `.vigolium-auth.lock` is missing → look for stray
//     `auth.json.vigolium-bak-*` files and report them as orphaned (the
//     operator must resolve, since we can't tell which one was active).
//   - If the lock is present but its PID is alive → record as held and
//     leave everything intact.
//   - If the lock is present but its PID is dead → restore the matching
//     `auth.json.vigolium-bak-<runUUID>` over `auth.json` and remove the
//     lock. Non-matching backups are reported as orphaned for manual
//     resolution.
//
// Returns a structured summary so the caller can log a single line. Never
// errors — sweep is best-effort by design (a stuck cred file is an
// operator problem, not a vigolium-must-fail-boot problem).
func SweepStalePioliumAuth(piAgentDirs []string) PioliumSweepResult {
	var res PioliumSweepResult
	for _, dir := range piAgentDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		lockPath := filepath.Join(dir, pioliumAuthLockFileName)
		target := filepath.Join(dir, pioliumAuthFileName)

		var backups []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if strings.HasPrefix(e.Name(), pioliumAuthBackupPrefix) {
				backups = append(backups, filepath.Join(dir, e.Name()))
			}
		}

		if _, err := os.Stat(lockPath); errors.Is(err, os.ErrNotExist) {
			res.Orphaned = append(res.Orphaned, backups...)
			continue
		}

		holder := readPioliumLockBreadcrumb(lockPath)
		if holder.PID > 0 && processIsAlive(holder.PID) {
			entry := PioliumSweepEntry{Dir: dir, LockPath: lockPath, Holder: holder}
			res.Held = append(res.Held, entry)
			continue
		}

		// Holder is dead → restore the matching backup if any.
		var matched string
		if holder.Run != "" {
			want := pioliumAuthBackupPrefix + holder.Run
			for _, b := range backups {
				if filepath.Base(b) == want {
					matched = b
					break
				}
			}
		}
		if matched == "" && len(backups) == 1 {
			// Single backup with no run hint — restore it.
			matched = backups[0]
		}
		if matched != "" {
			if err := os.Rename(matched, target); err != nil {
				res.Orphaned = append(res.Orphaned, matched)
			} else {
				res.Swept = append(res.Swept, PioliumSweepEntry{
					Dir: dir, LockPath: lockPath, BackupPath: matched, Holder: holder,
				})
			}
		}
		for _, b := range backups {
			if b != matched {
				res.Orphaned = append(res.Orphaned, b)
			}
		}
		_ = os.Remove(lockPath)
	}
	return res
}

// processIsAlive reports whether the given PID corresponds to a live
// process. Uses signal 0 (POSIX "check existence" idiom) — never sends a
// real signal, never errors when permission is denied (EPERM still means
// the PID exists).
func processIsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM = process exists but we can't signal it. ESRCH = no such PID.
	return errors.Is(err, syscall.EPERM)
}

// copyFileMode copies src to dst, creating dst with the given mode. Used
// instead of os.Link/io.Copy on a pre-opened file so the staged auth.json
// always has 0o600 even if the source had looser permissions.
func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
