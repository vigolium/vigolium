package database

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
)

// mergeLockStaleAfter is how long a merge lock file may sit untouched before a
// waiting process treats it as abandoned (owner crashed mid-merge) and steals
// it. A merge is a seconds-long bulk copy, so this is generously above any
// healthy hold time.
const mergeLockStaleAfter = 5 * time.Minute

// WithMergeLock runs fn while holding a best-effort cross-process advisory lock
// for destPath, serializing concurrent merges into the same destination
// database. The lock is an O_EXCL sentinel file (<destPath>.merge-lock), which
// is portable across platforms and needs no syscall-level file locking.
//
// It is intentionally best-effort: if the lock cannot be acquired within
// timeout, fn runs anyway and relies on SQLite's own busy_timeout + the
// merge's retry-on-busy loop for correctness. The lock is an optimization that
// keeps staggered finishers from contending, not a correctness requirement, so
// a stale or contended lock degrades to DB-level serialization rather than
// failing the merge.
func WithMergeLock(destPath string, timeout time.Duration, fn func() error) error {
	lockPath := destPath + ".merge-lock"
	release, acquired := acquireMergeLock(lockPath, timeout)
	if !acquired {
		zap.L().Debug("merge lock not acquired within timeout; proceeding with DB-level serialization",
			zap.String("lock", lockPath))
	}
	defer release()
	return fn()
}

// acquireMergeLock spins on an O_CREATE|O_EXCL sentinel until it wins the lock,
// the timeout elapses, or a stale lock is reclaimed. It returns a release
// function (a no-op when the lock was not acquired) and whether the lock is
// held.
func acquireMergeLock(lockPath string, timeout time.Duration) (release func(), acquired bool) {
	deadline := time.Now().Add(timeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = fmt.Fprintf(f, "pid=%d at=%s\n", os.Getpid(), time.Now().Format(time.RFC3339Nano))
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, true
		}
		if !os.IsExist(err) {
			// Unexpected error (e.g. unwritable directory): give up the lock and
			// let the caller proceed without it.
			return func() {}, false
		}
		// Someone holds it. Reclaim it if it looks abandoned.
		if info, statErr := os.Stat(lockPath); statErr == nil {
			if time.Since(info.ModTime()) > mergeLockStaleAfter {
				zap.L().Warn("reclaiming stale merge lock", zap.String("lock", lockPath))
				_ = os.Remove(lockPath)
				continue
			}
		}
		if time.Now().After(deadline) {
			return func() {}, false
		}
		time.Sleep(75 * time.Millisecond)
	}
}
