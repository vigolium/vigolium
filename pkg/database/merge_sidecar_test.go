package database

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func sidecarsOf(path string) []string {
	var out []string
	for _, suf := range sqliteSidecars {
		if _, err := os.Stat(path + suf); err == nil {
			out = append(out, suf)
		}
	}
	return out
}

// A merge reads its source without leaving sidecars beside it.
func TestMergeLeavesNoSidecars(t *testing.T) {
	ctx := context.Background()
	src, srcPath := newFileDB(t, "src.sqlite")
	insertHTTPRecord(t, src, "r1", DefaultProjectUUID)
	require.NoError(t, src.Close())
	require.Empty(t, sidecarsOf(srcPath), "precondition: a cleanly closed source has no sidecars")

	dst, _ := newFileDB(t, "dst.sqlite")
	stats, err := MergeSQLiteFile(ctx, dst, srcPath)
	require.NoError(t, err)
	require.Equal(t, 1, stats.RecordsMerged)
	require.Empty(t, sidecarsOf(srcPath), "an immutable attach must create no -wal/-shm")
}

// A source with an uncheckpointed WAL is read whole (immutable would lose the
// WAL rows), and the sidecars the read created are removed; a read-only
// directory is read through a scratch copy.
func TestMergeLiveWALSource(t *testing.T) {
	ctx := context.Background()
	live, livePath := newFileDB(t, "live.sqlite")
	insertHTTPRecord(t, live, "r-wal", DefaultProjectUUID)

	// Snapshot the main file and its WAL while the writer still holds them.
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "snap.sqlite")
	require.NoError(t, copyFile(livePath, srcPath))
	require.NoError(t, copyFile(livePath+"-wal", srcPath+"-wal"))
	require.True(t, hasLiveWAL(srcPath), "precondition: the snapshot carries a live WAL")

	dst, _ := newFileDB(t, "dst.sqlite")
	stats, err := MergeSQLiteFile(ctx, dst, srcPath)
	require.NoError(t, err)
	require.Equal(t, 1, stats.RecordsMerged, "the WAL's rows must be read")
	require.Equal(t, []string{"-wal"}, sidecarsOf(srcPath), "only the sidecar that was already there remains")

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	require.NoError(t, os.Remove(srcPath+"-wal"))
	require.NoError(t, copyFile(livePath+"-wal", srcPath+"-wal"))
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	dst2, _ := newFileDB(t, "dst2.sqlite")
	stats, err = MergeSQLiteFile(ctx, dst2, srcPath)
	require.NoError(t, err)
	require.Equal(t, 1, stats.RecordsMerged)
}

func TestIsSQLiteSidecar(t *testing.T) {
	for p, want := range map[string]bool{"a.sqlite": false, "a.sqlite-wal": true, "a.sqlite-shm": true, "a.db-journal": true} {
		require.Equal(t, want, IsSQLiteSidecar(p), p)
	}
}
