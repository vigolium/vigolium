package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/scratch"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// A SQLite database is the main file plus whatever is in its WAL. Moving only
// the main file would silently drop every transaction committed since the last
// checkpoint — a recovery that loses the most recent findings is worse than one
// that says it failed.
func TestPreserveWorkingDBMovesSidecars(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	src := filepath.Join(t.TempDir(), "x.sqlite")
	require.NoError(t, os.WriteFile(src, []byte("main"), 0o600))
	require.NoError(t, os.WriteFile(src+"-wal", []byte("wal"), 0o600))

	dest, err := preserveWorkingDB(src, "isolate")
	require.NoError(t, err)

	assert.True(t, filepath.IsAbs(dest), "the message names this path, so it must be absolute")
	assert.Contains(t, dest, filepath.Join(home, ".vigolium", "recovered"))
	assert.Contains(t, filepath.Base(dest), "isolate-")
	assert.True(t, strings.HasSuffix(dest, "x.sqlite"))

	assert.Equal(t, "main", readFileString(t, dest))
	assert.Equal(t, "wal", readFileString(t, dest+"-wal"))

	// Moved, not copied: leaving the original behind would keep the scratch
	// directory's disk and give two paths that both look authoritative.
	assert.NoFileExists(t, src)
	assert.NoFileExists(t, src+"-wal")

	// A whole scan's traffic, including captured credentials.
	for _, p := range []string{dest, dest + "-wal"} {
		info, serr := os.Stat(p)
		require.NoError(t, serr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s", p)
	}
	info, err := os.Stat(filepath.Dir(dest))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

// A -shm file that does not exist is not a failure: a cleanly checkpointed
// database has none.
func TestPreserveWorkingDBWithoutSidecars(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	src := filepath.Join(t.TempDir(), "plain.sqlite")
	require.NoError(t, os.WriteFile(src, []byte("main"), 0o600))

	dest, err := preserveWorkingDB(src, "stateless")
	require.NoError(t, err)
	assert.Equal(t, "main", readFileString(t, dest))
	assert.NoFileExists(t, dest+"-wal")
}

// --keep-db-on-error is the whole point of releaseStatelessDB: on a failure the
// working database moves out of scratch and the error names where it went.
func TestReleaseStatelessDBKeepsOnError(t *testing.T) {
	orig := globalKeepDBOnError
	t.Cleanup(func() { globalKeepDBOnError = orig })
	t.Setenv("HOME", t.TempDir())

	newWorkingDB := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "stateless-run.sqlite")
		require.NoError(t, os.WriteFile(p, []byte("results"), 0o600))
		return p
	}

	t.Run("failure with the flag preserves and names the path", func(t *testing.T) {
		globalKeepDBOnError = true
		path := newWorkingDB(t)
		runErr := codedErrorf(apicontract.CodeExportFailed, "write report.html: no such directory")

		got := releaseStatelessDB(path, runErr)
		require.Error(t, got)

		// The classification has to survive the wrapping, or the exit code and the
		// -j error code change just because the operator asked to keep the file.
		assert.True(t, isExportFailure(got), "%%w must preserve the coded error")
		assert.Equal(t, ExitError, classifyExitCode(got))

		assert.Contains(t, got.Error(), "working database kept at")
		assert.Contains(t, got.Error(), "vigolium finding -S --db")
		assert.NoFileExists(t, path, "the working database moved out of scratch")

		// The path in the message exists, which is the assertion the old
		// db-isolate hint failed.
		named := namedKeptPath(t, got.Error())
		assert.FileExists(t, named)
		assert.Equal(t, "results", readFileString(t, named))
	})

	t.Run("failure without the flag still removes", func(t *testing.T) {
		globalKeepDBOnError = false
		path := newWorkingDB(t)
		runErr := errors.New("scan failed")

		got := releaseStatelessDB(path, runErr)
		assert.Equal(t, runErr, got, "the error is returned unchanged")
		assert.NoFileExists(t, path)
	})

	t.Run("success with the flag still removes", func(t *testing.T) {
		globalKeepDBOnError = true
		path := newWorkingDB(t)

		assert.NoError(t, releaseStatelessDB(path, nil))
		assert.NoFileExists(t, path, "a clean run's throwaway database is still thrown away")
	})

	t.Run("sidecars go too", func(t *testing.T) {
		globalKeepDBOnError = false
		path := newWorkingDB(t)
		require.NoError(t, os.WriteFile(path+"-wal", []byte("w"), 0o600))
		require.NoError(t, os.WriteFile(path+"-shm", []byte("s"), 0o600))

		_ = releaseStatelessDB(path, errors.New("boom"))
		assert.NoFileExists(t, path+"-wal")
		assert.NoFileExists(t, path+"-shm")
	})
}

// Without -S there is no throwaway database to keep, so the flag would be a
// control that protects nothing.
func TestKeepDBOnErrorRequiresStateless(t *testing.T) {
	orig := globalKeepDBOnError
	t.Cleanup(func() { globalKeepDBOnError = orig })

	globalKeepDBOnError = true
	err := validateKeepDBOnError(false)
	require.Error(t, err)
	assert.Equal(t, ExitUsageError, classifyExitCode(err))
	assert.Contains(t, err.Error(), "requires -S/--stateless")

	assert.NoError(t, validateKeepDBOnError(true))

	globalKeepDBOnError = false
	assert.NoError(t, validateKeepDBOnError(false))
}

// The db-isolate hint used to name a path inside process scratch, which
// releaseScratch deletes at exit — so the file the operator was told to go read
// was already being removed. The path named now outlives the scratch release.
func TestDBIsolateMergeFailureKeepsFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	require.NoError(t, scratch.Acquire())
	scratchFile, err := scratch.CreateTemp("isolate-*.sqlite")
	require.NoError(t, err)
	scratchPath := scratchFile.Name()
	require.NoError(t, scratchFile.Close())
	require.NoError(t, os.WriteFile(scratchPath, []byte("isolated-results"), 0o600))

	mergeErr := errors.New("destination database is read-only")
	got := dbIsolateMergeFailed(scratchPath, nil, mergeErr)
	require.Error(t, got)
	assert.ErrorIs(t, got, mergeErr)
	assert.Contains(t, got.Error(), "results kept at")

	// Release the scratch, which is what destroyed the old "preserved" file.
	scratch.Release()

	named := namedKeptPath(t, got.Error())
	assert.FileExists(t, named, "the preserved path must survive scratch release")
	assert.Equal(t, "isolated-results", readFileString(t, named))
}

// When the scan itself failed, that error is still what the command exits with —
// it is the more useful cause — but the kept path is appended so the operator
// learns about it either way.
func TestDBIsolateMergeFailureKeepsScanError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path := filepath.Join(t.TempDir(), "isolate.sqlite")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	scanErr := codedErrorf(apicontract.CodeExportFailed, "generate html report.html: denied")
	got := dbIsolateMergeFailed(path, scanErr, errors.New("merge broke"))
	require.Error(t, got)
	assert.ErrorIs(t, got, scanErr)
	assert.True(t, isExportFailure(got), "the scan's classification must survive")
	assert.Contains(t, got.Error(), "db-isolate results kept at")
}

// namedKeptPath pulls the recovered-database path back out of an error message,
// so the test asserts the path the operator is actually shown rather than one it
// recomputed itself.
func namedKeptPath(t *testing.T, msg string) string {
	t.Helper()
	for _, field := range strings.FieldsFunc(msg, func(r rune) bool {
		return r == ' ' || r == ';' || r == ')' || r == '(' || r == '\n'
	}) {
		if strings.Contains(field, ".vigolium/recovered/") {
			return field
		}
	}
	t.Fatalf("no recovered path in %q", msg)
	return ""
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

// An export failure keeps the stateless database without --keep-db-on-error:
// the results it holds are the only copy once the file could not be written.
func TestReleaseStatelessDBKeepsOnExportFailure(t *testing.T) {
	swapGlobal(t, &globalKeepDBOnError, false)
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "stateless-run.sqlite")
	require.NoError(t, os.WriteFile(path, []byte("results"), 0o600))

	got := releaseStatelessDB(path, codedErrorf(apicontract.CodePDFFailed, "render pdf: chrome missing"))
	require.Error(t, got)
	assert.Contains(t, got.Error(), "working database kept at")
	assert.FileExists(t, namedKeptPath(t, got.Error()))
	assert.NoFileExists(t, path)
}
