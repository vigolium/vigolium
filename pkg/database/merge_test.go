package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// newFileDB creates a schema-ready, file-backed SQLite database (merges need a
// real file path to ATTACH, so the in-memory newTestDB helper can't be used).
// Returns the open DB and its file path.
func newFileDB(t *testing.T, name string) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	cfg := &config.DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: config.SQLiteConfig{
			Path:        path,
			BusyTimeout: 5000,
			JournalMode: "WAL",
			Synchronous: "NORMAL",
			CacheSize:   2000,
		},
	}
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	if err := db.SeedDefaults(ctx); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func mustExec(t *testing.T, db *DB, q string, args ...any) sql.Result {
	t.Helper()
	res, err := db.ExecContext(context.Background(), q, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
	return res
}

func insertHTTPRecord(t *testing.T, db *DB, uuid, project string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO http_records
		(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
		VALUES (?, ?, 'https', 'example.com', 443, 'GET', ?, ?, 'HTTP/1.1', ?)`,
		uuid, project, "/"+uuid, "https://example.com/"+uuid, "rh-"+uuid)
}

func insertFinding(t *testing.T, db *DB, project, hash, recUUID string) int64 {
	t.Helper()
	res := mustExec(t, db, `INSERT INTO findings
		(project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash)
		VALUES (?, ?, 'xss', 'XSS', 'high', ?)`,
		project, `["`+recUUID+`"]`, hash)
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func scalarInt(t *testing.T, db *DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

func TestMergeSQLiteFile_BasicAndRemap(t *testing.T) {
	ctx := context.Background()
	const project = DefaultProjectUUID

	src, srcPath := newFileDB(t, "src.sqlite")
	mustExec(t, src, `INSERT INTO scans (uuid, project_uuid, status, target) VALUES (?, ?, 'completed', 'https://example.com')`, "scan-1", project)
	insertHTTPRecord(t, src, "rec1", project)
	insertHTTPRecord(t, src, "rec2", project)
	srcFID := insertFinding(t, src, project, "fh-1", "rec1")
	mustExec(t, src, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, srcFID, "rec1")
	mustExec(t, src, `INSERT INTO oast_interactions
		(project_uuid, unique_id, full_id, protocol, interacted_at, finding_id)
		VALUES (?, 'uid-1', 'uid-1.oast', 'dns', CURRENT_TIMESTAMP, ?)`, project, srcFID)
	// Mirror the real flow: the scan's DB handle is closed before the merge.
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}

	dest, _ := newFileDB(t, "dest.sqlite")
	stats, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatalf("MergeSQLiteFile: %v", err)
	}

	if stats.RecordsMerged != 2 || stats.FindingsMerged != 1 ||
		stats.FindingRecordsMerged != 1 || stats.OASTMerged != 1 || stats.ScansMerged != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// The destination assigns its own finding id; the junction and OAST FK must
	// point at the NEW id, not the source's.
	destFID := scalarInt(t, dest, `SELECT id FROM findings WHERE project_uuid = ? AND finding_hash = ?`, project, "fh-1")
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM finding_records WHERE finding_id = ? AND record_uuid = 'rec1'`, destFID); got != 1 {
		t.Fatalf("finding_records not remapped to dest id %d (count=%d)", destFID, got)
	}
	var oastFID sql.NullInt64
	if err := dest.QueryRowContext(ctx, `SELECT finding_id FROM oast_interactions LIMIT 1`).Scan(&oastFID); err != nil {
		t.Fatalf("query oast finding_id: %v", err)
	}
	if !oastFID.Valid || oastFID.Int64 != destFID {
		t.Fatalf("oast finding_id not remapped: got %v want %d", oastFID, destFID)
	}
}

// TestMergeSQLiteFileOptions pins the MergeOptions contracts the --glob-db
// readers rely on. One shared source — a scan, two records carrying bodies, a
// finding linked to rec1, and an OAST row on it — is merged under each option:
//
//   - default: everything copies, bodies included (the opt-in must default safe;
//     --search LIKEs over the bodies).
//   - SkipHTTPRecords: the finding reader's case — no records, but findings, the
//     junction and OAST still merge and remap.
//   - SkipRecordBodies: the traffic reader's case — every row lands with its
//     metadata (counts and metadata predicates unaffected) but no bodies.
func TestMergeSQLiteFileOptions(t *testing.T) {
	const project = DefaultProjectUUID
	seed := func(t *testing.T) string {
		src, srcPath := newFileDB(t, "src.sqlite")
		mustExec(t, src, `INSERT INTO scans (uuid, project_uuid, status, target) VALUES (?, ?, 'completed', 'https://example.com')`, "scan-1", project)
		insertHTTPRecord(t, src, "rec1", project)
		insertHTTPRecord(t, src, "rec2", project)
		mustExec(t, src, `UPDATE http_records SET raw_request = ?, raw_response = ?, status_code = 200`,
			[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), []byte("HTTP/1.1 200 OK\r\n\r\nbody"))
		srcFID := insertFinding(t, src, project, "fh-1", "rec1")
		mustExec(t, src, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, srcFID, "rec1")
		mustExec(t, src, `INSERT INTO oast_interactions
			(project_uuid, unique_id, full_id, protocol, interacted_at, finding_id)
			VALUES (?, 'uid-1', 'uid-1.oast', 'dns', CURRENT_TIMESTAMP, ?)`, project, srcFID)
		if err := src.Close(); err != nil {
			t.Fatalf("close src: %v", err)
		}
		return srcPath
	}

	for _, tc := range []struct {
		name        string
		opts        MergeOptions
		wantRecords int
		wantBodies  bool
	}{
		{"default copies everything", MergeOptions{}, 2, true},
		{"skip http_records", MergeOptions{SkipHTTPRecords: true}, 0, false},
		{"skip record bodies", MergeOptions{SkipRecordBodies: true}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srcPath := seed(t)
			dest, _ := newFileDB(t, "dest.sqlite")
			stats, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, tc.opts)
			if err != nil {
				t.Fatalf("merge: %v", err)
			}

			// http_records rows land unless the whole table is skipped.
			if stats.RecordsMerged != tc.wantRecords {
				t.Fatalf("RecordsMerged = %d, want %d", stats.RecordsMerged, tc.wantRecords)
			}
			if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records`); got != int64(tc.wantRecords) {
				t.Fatalf("http_records rows = %d, want %d", got, tc.wantRecords)
			}

			// Findings, the junction and OAST always merge and remap to the dest
			// id, whatever happens to the records.
			if stats.FindingsMerged != 1 || stats.FindingRecordsMerged != 1 || stats.OASTMerged != 1 || stats.ScansMerged != 1 {
				t.Fatalf("finding tables not merged: %+v", stats)
			}
			destFID := scalarInt(t, dest, `SELECT id FROM findings WHERE project_uuid = ? AND finding_hash = ?`, project, "fh-1")
			if got := scalarInt(t, dest, `SELECT COUNT(*) FROM finding_records WHERE finding_id = ? AND record_uuid = 'rec1'`, destFID); got != 1 {
				t.Fatalf("junction not remapped to dest id %d (count=%d)", destFID, got)
			}
			var oastFID sql.NullInt64
			if err := dest.QueryRowContext(ctx, `SELECT finding_id FROM oast_interactions LIMIT 1`).Scan(&oastFID); err != nil {
				t.Fatalf("query oast finding_id: %v", err)
			}
			if !oastFID.Valid || oastFID.Int64 != destFID {
				t.Fatalf("oast finding_id not remapped: got %v want %d", oastFID, destFID)
			}

			// Bodies survive only in the full copy; metadata always survives.
			nonNull := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records WHERE raw_request IS NOT NULL OR raw_response IS NOT NULL`)
			switch {
			case tc.wantBodies && nonNull != int64(tc.wantRecords):
				t.Fatalf("bodies missing: %d rows carry a body, want %d", nonNull, tc.wantRecords)
			case !tc.wantBodies && nonNull != 0:
				t.Fatalf("bodies present: %d rows retained a body, want 0", nonNull)
			}
			if tc.opts.SkipRecordBodies {
				if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records WHERE status_code = 200`); got != int64(tc.wantRecords) {
					t.Fatalf("metadata lost under SkipRecordBodies: %d rows status=200, want %d", got, tc.wantRecords)
				}
			}
		})
	}
}

func TestMergeSQLiteFile_Idempotent(t *testing.T) {
	ctx := context.Background()
	const project = DefaultProjectUUID

	src, srcPath := newFileDB(t, "src.sqlite")
	insertHTTPRecord(t, src, "rec1", project)
	fid := insertFinding(t, src, project, "fh-1", "rec1")
	mustExec(t, src, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, fid, "rec1")
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}

	dest, _ := newFileDB(t, "dest.sqlite")
	if _, err := MergeSQLiteFile(ctx, dest, srcPath); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	stats2, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}

	// Second merge must add nothing — everything dedups on its natural key.
	if stats2.RecordsMerged != 0 || stats2.FindingsMerged != 0 || stats2.FindingsDeduped != 1 {
		t.Fatalf("re-merge not idempotent: %+v", stats2)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records`); got != 1 {
		t.Fatalf("expected 1 record after re-merge, got %d", got)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM findings`); got != 1 {
		t.Fatalf("expected 1 finding after re-merge, got %d", got)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM finding_records`); got != 1 {
		t.Fatalf("expected 1 finding_record after re-merge, got %d", got)
	}
}

func TestMergeSQLiteFile_CrossProjectFindingHashCoexist(t *testing.T) {
	ctx := context.Background()

	// Destination already holds a finding with hash fh-1 under project A.
	dest, _ := newFileDB(t, "dest.sqlite")
	insertFinding(t, dest, "project-a", "fh-1", "recA")

	// Source carries the SAME finding_hash but under project B — dedup is
	// project-scoped, so it must coexist rather than be suppressed.
	src, srcPath := newFileDB(t, "src.sqlite")
	insertFinding(t, src, "project-b", "fh-1", "recB")
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}

	stats, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if stats.FindingsMerged != 1 || stats.FindingsDeduped != 0 {
		t.Fatalf("cross-project finding should insert, not dedup: %+v", stats)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM findings WHERE finding_hash = 'fh-1'`); got != 2 {
		t.Fatalf("expected fh-1 under both projects (2 rows), got %d", got)
	}
}

func TestMergeSQLiteFile_AgenticScan(t *testing.T) {
	ctx := context.Background()
	const project = DefaultProjectUUID
	const runUUID = "agentic-run-1"

	// Source carries an agentic_scans row (as autopilot/swarm write) plus a
	// finding linked to it by agentic_scan_uuid.
	src, srcPath := newFileDB(t, "src.sqlite")
	mustExec(t, src, `INSERT INTO agentic_scans (uuid, project_uuid, mode, agent_name, status) VALUES (?, ?, 'autopilot', 'olium', 'completed')`, runUUID, project)
	mustExec(t, src, `INSERT INTO findings
		(project_uuid, http_record_uuids, agentic_scan_uuid, module_id, module_name, severity, finding_hash)
		VALUES (?, '[]', ?, 'xss', 'XSS', 'high', 'fh-a')`, project, runUUID)
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}

	dest, _ := newFileDB(t, "dest.sqlite")
	stats, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if stats.AgenticScansMerged != 1 || stats.FindingsMerged != 1 {
		t.Fatalf("expected 1 agentic_scan + 1 finding, got %+v", stats)
	}
	// The agentic run row is preserved and the finding still links to it by uuid.
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM agentic_scans WHERE uuid = ?`, runUUID); got != 1 {
		t.Fatalf("expected agentic_scans row for %s, got %d", runUUID, got)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM findings WHERE agentic_scan_uuid = ?`, runUUID); got != 1 {
		t.Fatalf("expected finding linked to agentic run %s, got %d", runUUID, got)
	}

	// Re-merge is idempotent: agentic_scans dedups on its UNIQUE(uuid).
	stats2, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatalf("re-merge: %v", err)
	}
	if stats2.AgenticScansMerged != 0 {
		t.Fatalf("re-merge should not duplicate agentic_scans, got %+v", stats2)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM agentic_scans`); got != 1 {
		t.Fatalf("expected exactly 1 agentic_scans row after re-merge, got %d", got)
	}
}

func TestWithMergeLock_AcquireAndRelease(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "x.sqlite")
	lockPath := dest + ".merge-lock"

	ran := false
	err := WithMergeLock(dest, time.Second, func() error {
		ran = true
		if _, statErr := os.Stat(lockPath); statErr != nil {
			t.Errorf("lock file should exist while fn runs: %v", statErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithMergeLock: %v", err)
	}
	if !ran {
		t.Fatal("fn did not run")
	}
	if _, statErr := os.Stat(lockPath); !os.IsNotExist(statErr) {
		t.Fatalf("lock file should be removed after release, stat err=%v", statErr)
	}
}

func TestWithMergeLock_BestEffortWhenHeld(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "x.sqlite")
	lockPath := dest + ".merge-lock"
	// Pre-create a fresh (non-stale) lock owned by "someone else".
	if err := os.WriteFile(lockPath, []byte("pid=999999"), 0o644); err != nil {
		t.Fatalf("seed lock: %v", err)
	}

	ran := false
	err := WithMergeLock(dest, 150*time.Millisecond, func() error { ran = true; return nil })
	if err != nil {
		t.Fatalf("WithMergeLock: %v", err)
	}
	if !ran {
		t.Fatal("fn should still run best-effort when the lock can't be acquired")
	}
	// We never owned the lock, so we must not have deleted it.
	if _, statErr := os.Stat(lockPath); statErr != nil {
		t.Fatalf("must not remove a lock we didn't acquire: %v", statErr)
	}
}

func TestRetryOnBusy(t *testing.T) {
	ctx := context.Background()

	calls := 0
	err := retryOnBusy(ctx, func() error {
		calls++
		if calls < 3 {
			return errors.New("database is locked (5)")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}

	// A non-busy error returns immediately, no retries.
	calls = 0
	err = retryOnBusy(ctx, func() error { calls++; return errors.New("boom") })
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected boom error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("non-busy error must not retry, got %d calls", calls)
	}
}
