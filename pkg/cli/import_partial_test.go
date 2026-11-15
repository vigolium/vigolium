package cli

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
)

// A multi-source import continues past a bad source, lists every source with
// its outcome, fills the glob counters, names the destination as db_path and
// exits 1; --glob-strict stops at the first failure.
func TestImportGlobContinuesPastBadSource(t *testing.T) {
	e := newB5Env(t)
	dir := filepath.Join(e.home, "srcs")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	good := writeImportJSONL(t, e.home)
	data, err := os.ReadFile(good)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.jsonl"), data, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.jsonl"), []byte("not json at all\n"), 0o600))
	pattern := filepath.Join(dir, "*.jsonl")

	code, stdout, stderr := e.run(t, nil, "import", "--glob-db", pattern, "-j")
	require.Equal(t, 1, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.Equal(t, false, doc["ok"])
	require.EqualValues(t, 1, doc["sources_failed"])
	srcs := doc["sources"].([]any)
	require.Len(t, srcs, 2)
	require.Equal(t, "imported", srcs[0].(map[string]any)["status"])
	require.Equal(t, "failed", srcs[1].(map[string]any)["status"])
	require.Positive(t, doc["findings_saved"])
	gs := doc["glob_sources"].(map[string]any)
	require.EqualValues(t, 2, gs["matched"])
	require.EqualValues(t, 1, gs["loaded"])
	require.NotEqual(t, pattern, doc["db_path"], "db_path names the destination, not the sources")

	code, stdout, stderr = e.run(t, nil, "import", "--glob-db", pattern, "--glob-strict", "-j")
	require.Equal(t, 1, code, stderr)
	require.NotContains(t, stdout, `"sources"`)
}

// A SQLite file that is not a vigolium store is refused, not merged as zeros.
func TestImportRefusesForeignSQLite(t *testing.T) {
	foreign := filepath.Join(t.TempDir(), "foreign.sqlite")
	raw, err := sql.Open("sqlite", foreign)
	require.NoError(t, err)
	_, err = raw.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	dst := newDBAtPath(t, filepath.Join(t.TempDir(), "dst.sqlite"))
	_, err = database.MergeSQLiteFile(context.Background(), dst, foreign)
	var fe *database.ForeignStoreError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, apicontract.CodeSourceIncompatible, classifyErrorCode(err, 1))
}
