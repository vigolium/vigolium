package cli

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

// seedImportTwoHostSQLite writes a vigolium SQLite source with one record and
// one finding on each of two hosts.
func seedImportTwoHostSQLite(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "older-merged.sqlite")
	db := newDBAtPath(t, path)
	ctx := context.Background()
	for _, host := range []string{"app.example.com", "api.other.test"} {
		_, err := db.ExecContext(ctx, `INSERT INTO http_records
			(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
			VALUES (?, ?, 'https', ?, 443, 'GET', '/', ?, 'HTTP/1.1', ?)`,
			"rec-"+host, database.DefaultProjectUUID, host, "https://"+host+"/", "rh-"+host)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, `INSERT INTO findings
			(project_uuid, http_record_uuids, url, hostname, module_id, module_name, severity, finding_hash)
			VALUES (?, ?, ?, ?, 'xss', 'XSS', 'high', ?)`,
			database.DefaultProjectUUID, `["rec-`+host+`"]`, "https://"+host+"/", host, "fh-"+host)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())
	return path
}

// destCounts reads what an import left in the env's destination database.
func destCounts(t *testing.T, e *b5Env) (records map[string]int, findings int) {
	t.Helper()
	db := newDBAtPath(t, e.db)
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, `SELECT hostname, COUNT(*) FROM http_records GROUP BY hostname`)
	require.NoError(t, err)
	records = map[string]int{}
	for rows.Next() {
		var h string
		var n int
		require.NoError(t, rows.Scan(&h, &n))
		records[h] = n
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&findings))
	return records, findings
}

// `import <vigolium.sqlite> --host` merges only that host's rows.
func TestImportSQLiteHostFilters(t *testing.T) {
	e := newB5Env(t)
	src := seedImportTwoHostSQLite(t, t.TempDir())

	code, stdout, stderr := e.run(t, nil, "import", src, "--host", "*.EXAMPLE.com", "-j")
	require.Equal(t, 0, code, stderr)
	doc := oneDoc(t, stdout, stderr)
	require.EqualValues(t, 1, doc["records_merged"])
	require.EqualValues(t, 1, doc["findings_merged"])

	records, findings := destCounts(t, e)
	require.Equal(t, map[string]int{"app.example.com": 1}, records)
	require.Equal(t, 1, findings)
}

// `import <vigolium.sqlite> --skip-findings` merges records without findings,
// alone and combined with --host.
func TestImportSQLiteSkipFindings(t *testing.T) {
	for name, extra := range map[string][]string{
		"alone":     nil,
		"with host": {"--host", "api.other.test"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newB5Env(t)
			src := seedImportTwoHostSQLite(t, t.TempDir())
			args := append([]string{"import", src, "--skip-findings", "-j"}, extra...)
			code, stdout, stderr := e.run(t, nil, args...)
			require.Equal(t, 0, code, stderr)
			oneDoc(t, stdout, stderr)

			records, findings := destCounts(t, e)
			require.Equal(t, 0, findings)
			if extra == nil {
				require.Equal(t, map[string]int{"app.example.com": 1, "api.other.test": 1}, records)
			} else {
				require.Equal(t, map[string]int{"api.other.test": 1}, records)
			}
		})
	}
}

// --host and --skip-findings are refused (exit 2), not ignored, for a source
// that is not a vigolium SQLite database — and nothing is imported.
func TestImportSQLiteOnlyFlagsRefusedElsewhere(t *testing.T) {
	for name, flag := range map[string][]string{
		"host":          {"--host", "a.example"},
		"skip-findings": {"--skip-findings"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newB5Env(t)
			src := writeImportJSONL(t, t.TempDir())
			code, _, stderr := e.run(t, nil, append([]string{"import", src}, flag...)...)
			require.Equal(t, ExitUsageError, code, stderr)
			require.Contains(t, stderr, flag[0])
			require.Contains(t, stderr, "JSONL")
			_, findings := destCounts(t, e)
			require.Equal(t, 0, findings, "a refused import wrote findings")
		})
	}
}

// --host takes one pattern; a comma is refused rather than read as a list the
// bridge path would not read the same way.
func TestImportSQLiteHostRefusesList(t *testing.T) {
	e := newB5Env(t)
	src := seedImportTwoHostSQLite(t, t.TempDir())
	code, _, stderr := e.run(t, nil, "import", src, "--host", "app.example.com,api.other.test")
	require.Equal(t, ExitUsageError, code, stderr)
	require.Contains(t, stderr, "one host pattern")
}

// --skip-findings has no meaning for a bridge pull.
func TestImportBridgeRefusesSkipFindings(t *testing.T) {
	e := newB5Env(t)
	code, _, stderr := e.run(t, nil, "import", "-B", "http://127.0.0.1:9", "--host", "a.example", "--skip-findings")
	require.Equal(t, ExitUsageError, code, stderr)
	require.Contains(t, stderr, "--skip-findings")
}

func TestVersionFeaturesPublishImportFilters(t *testing.T) {
	names := make([]string, 0, len(versionFeatures))
	for _, f := range versionFeatures {
		names = append(names, f.Name)
	}
	for _, want := range []string{"import-sqlite-host", "import-skip-findings"} {
		require.True(t, slices.Contains(names, want), "versionFeatures lacks %s: %s", want, strings.Join(names, ", "))
	}
}
