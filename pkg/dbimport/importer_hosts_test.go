package dbimport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// seedTwoHostSQLite writes a closed vigolium SQLite source holding one record
// and one finding on each of two hosts.
func seedTwoHostSQLite(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	srcPath := filepath.Join(t.TempDir(), "older-merged.sqlite")
	srcDB := newFileDBForTest(t, srcPath)
	for _, host := range []string{"app.example.com", "api.other.test"} {
		if _, err := srcDB.ExecContext(ctx, `INSERT INTO http_records
			(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
			VALUES (?, ?, 'https', ?, 443, 'GET', '/', ?, 'HTTP/1.1', ?)`,
			"rec-"+host, database.DefaultProjectUUID, host, "https://"+host+"/", "rh-"+host); err != nil {
			t.Fatalf("seed record: %v", err)
		}
		if _, err := srcDB.ExecContext(ctx, `INSERT INTO findings
			(project_uuid, http_record_uuids, url, hostname, module_id, module_name, severity, finding_hash)
			VALUES (?, ?, ?, ?, 'xss', 'XSS', 'high', ?)`,
			database.DefaultProjectUUID, `["rec-`+host+`"]`, "https://"+host+"/", host, "fh-"+host); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	if err := srcDB.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}
	return srcPath
}

func newDestRepo(t *testing.T) (*database.Repository, *database.DB) {
	t.Helper()
	destDB := newFileDBForTest(t, filepath.Join(t.TempDir(), "dest.sqlite"))
	t.Cleanup(func() { _ = destDB.Close() })
	return database.NewRepository(destDB), destDB
}

func countRows(t *testing.T, db *database.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

// TestImportPathSQLiteHosts pins that Options.Hosts reaches the merge: only the
// filtered host's record and finding land.
func TestImportPathSQLiteHosts(t *testing.T) {
	ctx := context.Background()
	srcPath := seedTwoHostSQLite(t)
	repo, db := newDestRepo(t)

	res, err := ImportPath(ctx, repo, srcPath, database.DefaultProjectUUID, Options{Hosts: []string{"*.EXAMPLE.com"}})
	if err != nil {
		t.Fatalf("ImportPath: %v", err)
	}
	if res.RecordsImported != 1 || res.FindingsSaved != 1 {
		t.Fatalf("imported records=%d findings=%d, want 1/1", res.RecordsImported, res.FindingsSaved)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM http_records WHERE hostname = 'api.other.test'`); n != 0 {
		t.Fatalf("filtered-out host's records landed: %d", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM findings WHERE hostname = 'app.example.com'`); n != 1 {
		t.Fatalf("filtered host's finding missing: %d", n)
	}
}

// TestImportPathSQLiteSkipFindingsWithHosts pins the records-only seeding a
// driver uses: one host's traffic, no findings.
func TestImportPathSQLiteSkipFindingsWithHosts(t *testing.T) {
	ctx := context.Background()
	srcPath := seedTwoHostSQLite(t)
	repo, db := newDestRepo(t)

	res, err := ImportPath(ctx, repo, srcPath, database.DefaultProjectUUID,
		Options{Hosts: []string{"app.example.com"}, SkipFindings: true})
	if err != nil {
		t.Fatalf("ImportPath: %v", err)
	}
	if res.RecordsImported != 1 || res.FindingsSaved != 0 {
		t.Fatalf("imported records=%d findings=%d, want 1/0", res.RecordsImported, res.FindingsSaved)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM findings`); n != 0 {
		t.Fatalf("findings landed under SkipFindings: %d", n)
	}
}

// TestImportPathHostsRefusedForNonSQLite pins that a host filter is refused,
// not ignored, for every source kind that cannot honour it — and that nothing
// is written.
func TestImportPathHostsRefusedForNonSQLite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	jsonlPath := filepath.Join(dir, "export.jsonl")
	if err := os.WriteFile(jsonlPath, []byte(jsonlRecordLine(t, "rec-x")+"\n"), 0o600); err != nil {
		t.Fatalf("write jsonl: %v", err)
	}
	auditDir := filepath.Join(dir, "audit")
	if err := os.Mkdir(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	for _, tc := range []struct {
		path string
		kind SourceKind
	}{
		{jsonlPath, SourceJSONL},
		{auditDir, SourceAudit},
	} {
		repo, db := newDestRepo(t)
		_, err := ImportPath(ctx, repo, tc.path, database.DefaultProjectUUID, Options{Hosts: []string{"example.com"}})
		var refusal *SQLiteOnlyOptionError
		if !errors.As(err, &refusal) {
			t.Fatalf("%s: err = %v, want SQLiteOnlyOptionError", tc.kind, err)
		}
		if refusal.Kind != tc.kind || !strings.Contains(err.Error(), tc.path) {
			t.Fatalf("refusal names the wrong source: %v", err)
		}
		if n := countRows(t, db, `SELECT COUNT(*) FROM http_records`); n != 0 {
			t.Fatalf("%s: refused import still wrote %d records", tc.kind, n)
		}
	}
}

func TestDetectSourceKind(t *testing.T) {
	dir := t.TempDir()
	jsonlPath := filepath.Join(dir, "x.jsonl")
	if err := os.WriteFile(jsonlPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, "x.zip")
	if err := os.WriteFile(zipPath, []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]SourceKind{
		seedTwoHostSQLite(t): SourceSQLite,
		jsonlPath:            SourceJSONL,
		zipPath:              SourceArchive,
		dir:                  SourceAudit,
	} {
		got, err := DetectSourceKind(path)
		if err != nil || got != want {
			t.Errorf("DetectSourceKind(%s) = %q, %v; want %q", path, got, err, want)
		}
	}
	if _, err := DetectSourceKind(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing path detected as a kind")
	}
}
