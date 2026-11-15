package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// recoveredDBDir is where a working database that would otherwise be deleted is
// moved so the operator can still read it.
//
// It is deliberately NOT under process scratch. The thing that made the old
// db-isolate message a false promise was that "preserved" named a path inside
// the directory scratch.Release removes on the way out — the file was gone
// before the operator finished reading the sentence. A recovered database lives
// outside every automatic sweep, and is the operator's to delete.
const recoveredDBDir = "~/.vigolium/recovered"

// globalKeepDBOnError backs --keep-db-on-error: on a failed stateless run, move
// the throwaway working database somewhere readable instead of deleting it.
//
// A stateless scan's database is removed unconditionally when the run returns,
// which is correct on the happy path — the results have been exported and the
// file is scratch. On a failure it is the only copy of everything the scan did
// learn before it broke, and deleting it means the next attempt re-crawls and
// re-attacks the target from zero. Opt-in because the default lifetime is what
// "stateless" promises.
var globalKeepDBOnError bool

// validateKeepDBOnError rejects --keep-db-on-error without -S/--stateless.
//
// A persisted scan has no throwaway database to keep: its results are already in
// the store the operator pointed at. Accepting the flag there would be a control
// that looks like it protects something and does nothing — exactly the shape
// this plan exists to remove — so it is a usage error (exit 2) rather than a
// silent no-op.
func validateKeepDBOnError(stateless bool) error {
	if globalKeepDBOnError && !stateless {
		return usageErrorf("--keep-db-on-error requires -S/--stateless: without it the scan already writes to a database that is not deleted")
	}
	return nil
}

// releaseStatelessDB is the end-of-run disposition for a stateless working
// database. It removes the file (and its sidecars) on the normal path, and under
// --keep-db-on-error moves it out of scratch when the run failed, folding the
// new location into the returned error.
//
// The error is wrapped with %w so its classification survives: the coded errors
// from WP2's export failures, the gate, and the usage errors all still decide
// the exit code and the machine error code.
func releaseStatelessDB(path string, runErr error) error {
	if path == "" {
		return runErr
	}
	// A run whose only failure is an output it could not write still holds its
	// results in this database: keep it, so they are not lost with the file.
	if runErr != nil && (globalKeepDBOnError || isExportFailure(runErr)) {
		kept, keepErr := preserveWorkingDB(path, "stateless")
		if keepErr == nil {
			return fmt.Errorf("%w (working database kept at %s; inspect with: vigolium finding -S --db %s)",
				runErr, kept, kept)
		}
		fmt.Fprintf(os.Stderr, "%s --keep-db-on-error: could not preserve %s: %v\n",
			terminal.WarnPrefix(), path, keepErr)
		// Fall through to removal: the file is in scratch, which is swept anyway,
		// and leaving it would only make the failure quieter.
	}
	removeWorkingDB(path)
	return runErr
}

// removeWorkingDB deletes a SQLite file and its WAL sidecars.
func removeWorkingDB(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
}

// preserveWorkingDB moves a working SQLite database (plus any -wal/-shm
// sidecars) out of harm's way and returns the absolute destination path.
//
// kind names the situation in the file name ("isolate", "stateless"), so a
// directory with several recoveries in it says which run produced which.
func preserveWorkingDB(path, kind string) (string, error) {
	dir := config.ExpandPath(recoveredDBDir)
	// 0700: a recovered working database holds a whole scan's traffic, including
	// whatever credentials and session cookies it captured.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}

	stamp := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(dir, fmt.Sprintf("%s-%s-%s", kind, stamp, filepath.Base(path)))

	if err := moveFile(path, dest); err != nil {
		return "", err
	}
	// Sidecars are moved on a best-effort basis: a checkpointed database is
	// complete without them, and failing the whole recovery over a -shm file
	// would throw away the results this exists to keep. They are moved when
	// present because a -wal that is NOT checkpointed holds committed
	// transactions, and leaving it behind would silently truncate the recovery.
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suffix); err == nil {
			_ = moveFile(path+suffix, dest+suffix)
		}
	}

	// Best-effort absolute: the path is usable either way, and Abs failing is not
	// worth losing a recovered database over.
	return absOrRaw(dest), nil
}

// moveFile renames src to dst, falling back to a copy when the rename cannot
// cross whatever is between them.
//
// The fallback is the point: scratch lives in $TMPDIR, which on a container or a
// CI runner is routinely a different filesystem from $HOME, and os.Rename fails
// with EXDEV there. A recovery that only worked on a developer laptop would be
// worse than none, because it would be the message that gets trusted.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	// The original is removed only after the copy is complete and synced, so an
	// interrupted recovery leaves the source rather than nothing.
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("remove %s after copying to %s: %w", src, dst, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("sync %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
