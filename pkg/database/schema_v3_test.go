package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// v3Columns are the columns schema v3 added to pre-existing tables.
var v3Columns = map[string][]string{
	"findings": {"status_note", "status_actor", "status_updated_at", "origin_record_uuid",
		"insertion_point", "payload", "verification", "verified_at"},
	"scans": {"plan", "heartbeat_at", "current_phase", "pid", "runner_host",
		"module_errors", "extensions_failed"},
	"schema_meta": {"observation_history_since"},
}

// v3Tables are the tables schema v3 introduced.
var v3Tables = []string{"finding_observations", "finding_status_events", "oast_payloads"}

// downgradeToV2 rewrites a current store into the shape a v2 binary left it in:
// no v3 tables, no v3 columns, version 2.
func downgradeToV2(t *testing.T, db *DB) {
	t.Helper()
	for _, tbl := range v3Tables {
		mustExec(t, db, "DROP TABLE "+tbl)
	}
	for tbl, cols := range v3Columns {
		for _, c := range cols {
			mustExec(t, db, fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", tbl, c))
		}
	}
	mustExec(t, db, "UPDATE schema_meta SET version = 2, min_reader_version = 1 WHERE id = 1")
}

// TestSchemaV3_MigratesV2Store upgrades a v2 store holding findings: the v3
// columns and tables appear, the version moves to 3 with the reader floor
// unchanged, and each finding with a scan gets exactly one backfilled
// observation carrying its found_at.
func TestSchemaV3_MigratesV2Store(t *testing.T) {
	ctx := context.Background()
	db, path := newFileDB(t, "v2.sqlite")
	scanA := uuid.NewString()
	scanB := uuid.NewString()
	// Raw inserts: the rows a v2 binary wrote, without v3 columns.
	mustExec(t, db, `INSERT INTO findings (project_uuid, http_record_uuids, scan_uuid, module_id, module_name, severity, finding_hash, found_at)
		VALUES (?, '[]', ?, 'm', 'M', 'high', 'h-a', '2026-01-02 03:04:05')`, DefaultProjectUUID, scanA)
	mustExec(t, db, `INSERT INTO findings (project_uuid, http_record_uuids, scan_uuid, module_id, module_name, severity, finding_hash)
		VALUES (?, '[]', ?, 'm', 'M', 'low', 'h-b')`, DefaultProjectUUID, scanB)
	mustExec(t, db, `INSERT INTO findings (project_uuid, http_record_uuids, module_id, module_name, severity, finding_hash)
		VALUES (?, '[]', 'm', 'M', 'low', 'h-noscan')`, DefaultProjectUUID)
	downgradeToV2(t, db)
	_ = db.Close()

	// A read-intent open reports the v2 store as outdated, naming v3 objects.
	r := openReaderFile(t, path)
	var outdated *SchemaOutdatedError
	if err := r.CheckSchema(ctx); !errors.As(err, &outdated) {
		t.Fatalf("CheckSchema on v2 store = %v, want SchemaOutdatedError", err)
	}

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	res, err := w.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.FromVersion != 2 || res.ToVersion != currentSchemaVersion || res.MinReaderVersion != minReaderVersion {
		t.Fatalf("Migrate result = %+v, want 2 -> %d with min_reader %d", res, currentSchemaVersion, minReaderVersion)
	}
	if err := r.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema after migrate = %v", err)
	}

	cols, err := listAllColumns(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	for tbl, want := range v3Columns {
		for _, c := range want {
			if !cols[tbl][c] {
				t.Errorf("column %s.%s missing after migration", tbl, c)
			}
		}
	}
	for _, tbl := range v3Tables {
		if !w.tableExists(ctx, tbl) {
			t.Errorf("table %s missing after migration", tbl)
		}
	}

	// Backfill: one row per finding with a scan, observed_at = found_at.
	if n := scalarInt(t, w, "SELECT COUNT(*) FROM finding_observations"); n != 2 {
		t.Fatalf("backfilled observations = %d, want 2 (the scan-less finding gets none)", n)
	}
	var observed string
	if err := w.QueryRowContext(ctx,
		"SELECT o.observed_at FROM finding_observations o JOIN findings f ON f.id = o.finding_id WHERE f.finding_hash = 'h-a'").
		Scan(&observed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(observed, "2026-01-02") {
		t.Errorf("observed_at = %q, want the finding's found_at", observed)
	}
	if n := scalarInt(t, w, "SELECT COUNT(*) FROM finding_observations WHERE scan_uuid = ? AND finding_hash = 'h-b'", scanB); n != 1 {
		t.Errorf("observation for h-b/scanB = %d, want 1", n)
	}

	since, err := NewRepository(w).ObservationHistorySince(ctx)
	if err != nil || since.IsZero() {
		t.Fatalf("observation_history_since = %v, %v; want set", since, err)
	}

	// Re-running the migration is a no-op: the backfill is gated and the
	// marker never moves.
	mustExec(t, w, "DELETE FROM finding_observations")
	if err := w.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, w, "SELECT COUNT(*) FROM finding_observations"); n != 0 {
		t.Errorf("backfill re-ran on a v3 store: %d rows", n)
	}
	again, _ := NewRepository(w).ObservationHistorySince(ctx)
	if !again.Equal(since) {
		t.Errorf("observation_history_since moved: %v -> %v", since, again)
	}
}

// TestSchemaV3_FreshStoreHasHistoryMarker: a new store records complete history
// from creation.
func TestSchemaV3_FreshStoreHasHistoryMarker(t *testing.T) {
	db := newTestDB(t)
	since, err := NewRepository(db).ObservationHistorySince(context.Background())
	if err != nil || since.IsZero() {
		t.Fatalf("fresh store observation_history_since = %v, %v", since, err)
	}
	if v := db.schemaVersion(context.Background()); v != currentSchemaVersion {
		t.Fatalf("fresh version = %d", v)
	}
}

func observationScans(t *testing.T, db *DB, findingID int64) []string {
	t.Helper()
	var scans []string
	if err := db.NewRaw("SELECT scan_uuid FROM finding_observations WHERE finding_id = ? ORDER BY scan_uuid", findingID).
		Scan(context.Background(), &scans); err != nil {
		t.Fatal(err)
	}
	return scans
}

func findingIDByHash(t *testing.T, db *DB, hash string) int64 {
	t.Helper()
	return scalarInt(t, db, "SELECT id FROM findings WHERE finding_hash = ?", hash)
}

// TestFindingObservations_WrittenOnInsertAndRedetection covers every save path:
// the event path, its batch form, and the direct (agent) path.
func TestFindingObservations_WrittenOnInsertAndRedetection(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	scan1, scan2, scan3 := "scan-1", "scan-2", "scan-3"

	ev := &output.ResultEvent{
		ModuleID: "m",
		Info:     output.Info{Name: "M", Severity: severity.High, Confidence: severity.Firm},
		URL:      "https://e.example/a",
	}
	var conv Finding
	if err := conv.FromResultEvent(ev); err != nil || conv.FindingHash == "" {
		t.Fatalf("FromResultEvent: %v (hash %q)", err, conv.FindingHash)
	}
	hash := conv.FindingHash
	if err := repo.SaveFinding(ctx, ev, nil, scan1, ""); err != nil {
		t.Fatal(err)
	}
	fid := findingIDByHash(t, db, hash)
	// Re-detection by a later scan, and a repeat within it.
	if err := repo.SaveFinding(ctx, ev, nil, scan2, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveFinding(ctx, ev, nil, scan2, ""); err != nil {
		t.Fatal(err)
	}
	// Batch path re-detection.
	if err := repo.SaveFindingsBatch(ctx, []FindingWrite{{Event: ev, ScanUUID: scan3}}); err != nil {
		t.Fatal(err)
	}
	if got, want := observationScans(t, db, fid), []string{scan1, scan2, scan3}; !slices.Equal(got, want) {
		t.Fatalf("observations = %v, want %v", got, want)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE finding_hash = ? AND project_uuid = ?", hash, DefaultProjectUUID); n != 3 {
		t.Errorf("observations carry hash/project: %d rows, want 3", n)
	}

	// Direct path with a scan records one; without a scan records none.
	direct := &Finding{ModuleID: "agent", ModuleName: "Agent", Severity: "low", Confidence: "firm",
		FindingHash: "obs-direct", ScanUUID: scan1, Status: StatusDraft}
	if err := repo.SaveFindingDirect(ctx, direct); err != nil {
		t.Fatal(err)
	}
	if got := observationScans(t, db, direct.ID); !slices.Equal(got, []string{scan1}) {
		t.Errorf("direct save observations = %v", got)
	}
	noScan := &Finding{ModuleID: "imp", ModuleName: "Imp", Severity: "low", Confidence: "firm", FindingHash: "obs-noscan"}
	if err := repo.SaveFindingDirect(ctx, noScan); err != nil {
		t.Fatal(err)
	}
	if got := observationScans(t, db, noScan.ID); len(got) != 0 {
		t.Errorf("scan-less save wrote observations %v", got)
	}

	// Batch direct path (importers).
	batch := &Finding{ModuleID: "b", ModuleName: "B", Severity: "low", Confidence: "firm", FindingHash: "obs-batch", ScanUUID: scan2}
	if _, err := repo.SaveFindingsDirectBatch(ctx, []*Finding{batch}); err != nil {
		t.Fatal(err)
	}
	if got := observationScans(t, db, batch.ID); !slices.Equal(got, []string{scan2}) {
		t.Errorf("direct batch observations = %v", got)
	}

	obs, err := repo.ListFindingObservations(ctx, DefaultProjectUUID, fid)
	if err != nil || len(obs) != 3 {
		t.Fatalf("ListFindingObservations = %d, %v", len(obs), err)
	}
}

// TestFindingV3Fields_RoundTrip: the new JSON and timestamp columns read back
// as written, and an unset one stays NULL.
func TestFindingV3Fields_RoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	now := time.Now().UTC().Truncate(time.Second)
	f := &Finding{ModuleID: "m", ModuleName: "M", Severity: "high", Confidence: "firm", FindingHash: "v3-rt",
		Status: StatusConfirmed, StatusNote: "reproduced", StatusActor: "alice", StatusUpdatedAt: &now,
		OriginRecordUUID: "rec-1", InsertionPoint: &FindingInsertionPoint{Type: "URL_PARAM", Name: "id"},
		Payload: "' OR 1=1--", Verification: &FindingVerification{Verdict: VerdictConfirmed, At: now, ScanUUID: "s"},
		VerifiedAt: &now}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetFindingByID(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusConfirmed || got.StatusNote != "reproduced" || got.StatusActor != "alice" ||
		got.OriginRecordUUID != "rec-1" || got.Payload != f.Payload {
		t.Errorf("scalar fields = %+v", got)
	}
	if got.InsertionPoint == nil || *got.InsertionPoint != *f.InsertionPoint {
		t.Errorf("insertion_point = %+v", got.InsertionPoint)
	}
	if got.Verification == nil || got.Verification.Verdict != VerdictConfirmed || !got.Verification.At.Equal(now) {
		t.Errorf("verification = %+v", got.Verification)
	}
	if got.VerifiedAt == nil || !got.VerifiedAt.Equal(now) || got.StatusUpdatedAt == nil {
		t.Errorf("timestamps = %v / %v", got.VerifiedAt, got.StatusUpdatedAt)
	}

	plain := &Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", FindingHash: "v3-plain"}
	if err := repo.SaveFindingDirect(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM findings WHERE id = ? AND insertion_point IS NULL AND verification IS NULL AND verified_at IS NULL", plain.ID); n != 1 {
		t.Error("unset v3 finding columns are not NULL")
	}
	// The finding JSON omits unset v3 fields, so `finding -j` output is unchanged
	// for findings that never had them.
	b, _ := json.Marshal(plain)
	for _, k := range []string{"status_note", "insertion_point", "verification", "verified_at", "status_updated_at"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("unset %s serialized: %s", k, b)
		}
	}
}

// TestScanV3Fields_RoundTrip covers the scans liveness/plan columns.
func TestScanV3Fields_RoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	hb := time.Now().UTC().Truncate(time.Second)
	sc := &Scan{UUID: uuid.NewString(), ProjectUUID: DefaultProjectUUID, Status: "running",
		Plan: json.RawMessage(`{"phases":["discovery"]}`), HeartbeatAt: &hb, CurrentPhase: "discovery",
		PID: 4242, RunnerHost: "host-a", ModuleErrors: map[string]int64{"ext-x": 3}, ExtensionsFailed: []string{"bad.js"}}
	if err := repo.CreateScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got := &Scan{}
	if err := db.NewSelect().Model(got).Where("uuid = ?", sc.UUID).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	var plan map[string][]string
	if err := json.Unmarshal(got.Plan, &plan); err != nil || len(plan["phases"]) != 1 {
		t.Errorf("plan = %s (%v)", got.Plan, err)
	}
	if got.HeartbeatAt == nil || !got.HeartbeatAt.Equal(hb) || got.CurrentPhase != "discovery" || got.PID != 4242 ||
		got.RunnerHost != "host-a" || got.ModuleErrors["ext-x"] != 3 || !slices.Equal(got.ExtensionsFailed, []string{"bad.js"}) {
		t.Errorf("scan v3 fields = %+v", got)
	}
}

// TestOASTPayload_RoundTrip: the nonce is the key.
func TestOASTPayload_RoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	p := &OASTPayload{Nonce: "cv1abc", ProjectUUID: DefaultProjectUUID, ScanUUID: "s", Class: "ssrf",
		ModuleID: "ssrf_blind", TargetURL: "https://t.example/", Param: "url", Payload: "http://cv1abc.oast.example"}
	if _, err := db.NewInsert().Model(p).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NewInsert().Model(p).Exec(ctx); err == nil {
		t.Error("duplicate nonce accepted; nonce must be unique")
	}
	got := &OASTPayload{}
	if err := db.NewSelect().Model(got).Where("nonce = ?", p.Nonce).Scan(ctx); err != nil || got.Class != "ssrf" || got.Param != "url" {
		t.Errorf("oast payload = %+v, %v", got, err)
	}
}

func TestFindingStatusVocabulary_Confirmed(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	for _, s := range FindingStatuses {
		if !IsValidFindingStatus(s) {
			t.Errorf("IsValidFindingStatus(%q) = false", s)
		}
	}
	if !slices.Contains(FindingStatuses, StatusConfirmed) {
		t.Fatal("confirmed missing from FindingStatuses")
	}
	f := &Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", FindingHash: "voc"}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetFindingStatus(ctx, DefaultProjectUUID, f.ID, StatusConfirmed, "", ""); err != nil {
		t.Fatalf("UpdateFindingStatusScoped(confirmed): %v", err)
	}
}

// seedFindingHistory gives finding id one observation and one status event.
func seedFindingHistory(t *testing.T, db *DB, project string, findingID int64, hash, scan string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid, observed_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`, project, findingID, hash, scan)
	mustExec(t, db, `INSERT INTO finding_status_events (finding_id, project_uuid, from_status, to_status, note, actor, created_at)
		VALUES (?, ?, 'triaged', 'confirmed', 'n', 'a', '2026-05-06 07:08:09')`, findingID, project)
}

// TestMergeSQLiteFile_CarriesFindingHistory: observations and status events
// follow their finding into the destination with the id remapped — including
// onto a pre-existing destination finding the source deduped against — and a
// re-merge adds nothing. OAST payload context merges by nonce.
func TestMergeSQLiteFile_CarriesFindingHistory(t *testing.T) {
	ctx := context.Background()
	dest, _ := newFileDB(t, "dest.sqlite")
	src, srcPath := newFileDB(t, "src.sqlite")
	project := DefaultProjectUUID

	// Destination already holds the shared finding (different id) seen by scan-old.
	for i := 0; i < 3; i++ {
		insertFinding(t, dest, project, fmt.Sprintf("pad-%d", i), "r")
	}
	destShared := insertFinding(t, dest, project, "shared", "r")
	seedFindingHistory(t, dest, project, destShared, "shared", "scan-old")

	srcShared := insertFinding(t, src, project, "shared", "r")
	srcNew := insertFinding(t, src, project, "only-src", "r")
	mustExec(t, src, `INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid) VALUES (?, ?, 'shared', 'scan-new')`, project, srcShared)
	seedFindingHistory(t, src, project, srcNew, "only-src", "scan-new")
	mustExec(t, src, `INSERT INTO oast_payloads (nonce, project_uuid, scan_uuid, class) VALUES ('n1', ?, 'scan-new', 'ssrf')`, project)
	_ = src.Close()

	stats, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if stats.ObservationsMerged != 2 || stats.StatusEventsMerged != 1 {
		t.Errorf("stats = %+v, want 2 observations / 1 status event", stats)
	}
	if got := observationScans(t, dest, destShared); !slices.Equal(got, []string{"scan-new", "scan-old"}) {
		t.Errorf("shared finding observations = %v, want scan-new folded onto the existing id", got)
	}
	destNew := findingIDByHash(t, dest, "only-src")
	if got := observationScans(t, dest, destNew); !slices.Equal(got, []string{"scan-new"}) {
		t.Errorf("new finding observations = %v", got)
	}
	if n := scalarInt(t, dest, "SELECT COUNT(*) FROM finding_status_events WHERE finding_id = ? AND to_status = 'confirmed'", destNew); n != 1 {
		t.Errorf("status event not remapped onto new finding (%d)", n)
	}
	if n := scalarInt(t, dest, "SELECT COUNT(*) FROM oast_payloads WHERE nonce = 'n1'"); n != 1 {
		t.Errorf("oast payload not merged")
	}

	// Idempotent.
	again, err := MergeSQLiteFile(ctx, dest, srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if again.ObservationsMerged != 0 || again.StatusEventsMerged != 0 {
		t.Errorf("re-merge added history: %+v", again)
	}
	if n := scalarInt(t, dest, "SELECT COUNT(*) FROM finding_status_events"); n != 2 {
		t.Errorf("status events after re-merge = %d, want 2", n)
	}
}

// TestProjectMoveAndPurge_CarryFindingHistory: reassignment moves history with
// its findings, purge removes it.
func TestProjectMoveAndPurge_CarryFindingHistory(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	src, dst := uuid.NewString(), uuid.NewString()

	f := &Finding{ProjectUUID: src, ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm",
		FindingHash: "proj-h", ScanUUID: "scan-p"}
	if err := repo.SaveFindingDirect(ctx, f); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO finding_status_events (finding_id, project_uuid, to_status) VALUES (?, ?, 'fixed')`, f.ID, src)
	mustExec(t, db, `INSERT INTO oast_payloads (nonce, project_uuid) VALUES ('pn', ?)`, src)

	if err := repo.ReassignProjectData(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"finding_observations", "finding_status_events", "oast_payloads"} {
		if n := scalarInt(t, db, "SELECT COUNT(*) FROM "+tbl+" WHERE project_uuid = ?", dst); n != 1 {
			t.Errorf("%s not reassigned (%d rows in dst)", tbl, n)
		}
	}
	if err := repo.PurgeProjectData(ctx, dst); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"finding_observations", "finding_status_events", "oast_payloads"} {
		if n := scalarInt(t, db, "SELECT COUNT(*) FROM "+tbl); n != 0 {
			t.Errorf("%s left %d rows after purge", tbl, n)
		}
	}
}

// TestDeleteFinding_RemovesHistory covers the id- and hash-based deletes.
func TestDeleteFinding_RemovesHistory(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	a := &Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", FindingHash: "del-a", ScanUUID: "s1"}
	b := &Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", FindingHash: "del-b", ScanUUID: "s1"}
	for _, f := range []*Finding{a, b} {
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
		mustExec(t, db, `INSERT INTO finding_status_events (finding_id, project_uuid, to_status) VALUES (?, ?, 'fixed')`, f.ID, DefaultProjectUUID)
	}
	if err := repo.DeleteFinding(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteFindingByHash(ctx, DefaultProjectUUID, "del-b"); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range findingChildTables {
		if n := scalarInt(t, db, "SELECT COUNT(*) FROM "+tbl); n != 0 {
			t.Errorf("%s left %d rows after finding deletes", tbl, n)
		}
	}
}

// TestMigrateFindingHistory_FoldsOntoSurvivor: the dedup pass re-points
// history onto the survivor without violating the observation key.
func TestMigrateFindingHistory_FoldsOntoSurvivor(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)
	mk := func(hash string, scans ...string) int64 {
		f := &Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", FindingHash: hash, ScanUUID: scans[0]}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatal(err)
		}
		for _, s := range scans[1:] {
			mustExec(t, db, `INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid) VALUES (?, ?, ?, ?)`,
				DefaultProjectUUID, f.ID, hash, s)
		}
		return f.ID
	}
	survivor := mk("surv", "s1")
	d1 := mk("dup1", "s1", "s2")
	d2 := mk("dup2", "s2", "s3")
	mustExec(t, db, `INSERT INTO finding_status_events (finding_id, project_uuid, to_status) VALUES (?, ?, 'fixed')`, d1, DefaultProjectUUID)

	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateFindingHistoryTx(ctx, tx, survivor, []int64{d1, d2}); err != nil {
		t.Fatal(err)
	}
	if err := deleteFindingsByIDsTx(ctx, tx, []int64{d1, d2}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := observationScans(t, db, survivor); !slices.Equal(got, []string{"s1", "s2", "s3"}) {
		t.Errorf("survivor observations = %v", got)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_observations WHERE finding_hash <> 'surv'"); n != 0 {
		t.Errorf("%d observations still carry a duplicate's hash", n)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM finding_status_events WHERE finding_id = ?", survivor); n != 1 {
		t.Errorf("status event not re-pointed to survivor")
	}
}
