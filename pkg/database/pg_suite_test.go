package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Core repository scenarios, run against every dialect.
//
// Each scenario runs against SQLite always, and against Postgres when
// VIGOLIUM_PG_DSN names a server (CI's postgres job sets it; locally:
// `make postgres-up` then
// VIGOLIUM_PG_DSN=postgres://vigolium_test:vigolium_test_pass@localhost:5433/vigolium_test?sslmode=disable).
// Without the variable the Postgres half skips, so `go test -short` needs no
// server. The Postgres tests are named TestPg_ so CI can fail on a skip.
//
// The scenarios are the write and read paths whose SQL differs by dialect or
// whose column types do: bool, JSON, blob and timestamp round trips, ON
// CONFLICT upserts, the finding lifecycle tables, and project scoping.

// pgTestDSNEnv names the Postgres server the TestPg_ suite runs against.
const pgTestDSNEnv = "VIGOLIUM_PG_DSN"

// openPGTestDB returns an empty Postgres store with the current schema, or
// skips when VIGOLIUM_PG_DSN is unset. A set but unreachable DSN FAILS: CI
// sets it on purpose, and a skip there would pass green having tested nothing.
//
// Every schema table is dropped before and after, so tests share one database
// sequentially (the e2e TestPg_ suite uses the same server).
func openPGTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv(pgTestDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres test", pgTestDSNEnv)
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		t.Fatalf("%s set but Postgres unreachable: %v", pgTestDSNEnv, err)
	}
	db := &DB{DB: bun.NewDB(sqldb, pgdialect.New()), driver: driverPostgres}
	dropPGSchema(t, db)
	t.Cleanup(func() {
		dropPGSchema(t, db)
		_ = db.Close()
	})
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if err := db.SeedDefaults(context.Background()); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	return db
}

// dropPGSchema drops every table the schema templates declare.
func dropPGSchema(t *testing.T, db *DB) {
	t.Helper()
	for _, name := range parseDDLCatalog(t, schemaDDLStatements(driverPostgres)).order {
		if strings.HasPrefix(name, "idx_") {
			continue
		}
		if _, err := db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+name+" CASCADE"); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
	}
}

// coreRepositoryScenarios are the dialect-sensitive repository paths.
var coreRepositoryScenarios = []struct {
	name string
	run  func(t *testing.T, db *DB)
}{
	{"SchemaIdempotentAndReady", scenarioSchemaReady},
	{"RecordRoundTrip", scenarioRecordRoundTrip},
	{"FindingLifecycle", scenarioFindingLifecycle},
	{"ScanRowAndHeartbeat", scenarioScanRow},
	{"ScopesAndHostObservations", scenarioBoolColumns},
	{"ProjectIsolation", scenarioProjectIsolation},
}

func TestCoreRepository_SQLite(t *testing.T) {
	for _, sc := range coreRepositoryScenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, newTestDB(t)) })
	}
}

func TestPg_CoreRepository(t *testing.T) {
	if os.Getenv(pgTestDSNEnv) == "" {
		t.Skipf("%s not set; skipping Postgres test", pgTestDSNEnv)
	}
	for _, sc := range coreRepositoryScenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, openPGTestDB(t)) })
	}
}

// scenarioSchemaReady: a second CreateSchema is a no-op that succeeds, the
// readiness check finds nothing missing, and the store is at this version.
func scenarioSchemaReady(t *testing.T, db *DB) {
	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("second CreateSchema: %v", err)
	}
	if gaps := db.schemaGaps(ctx); len(gaps) != 0 {
		t.Fatalf("schema gaps on a fresh store: %v", gaps)
	}
	if err := db.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema: %v", err)
	}
	if v := db.schemaVersion(ctx); v != currentSchemaVersion {
		t.Fatalf("schema version %d, want %d", v, currentSchemaVersion)
	}
	if legacy, err := db.legacyBoolColumns(ctx); err != nil || len(legacy) != 0 {
		t.Fatalf("fresh store has legacy bool columns: %v, %v", legacy, err)
	}
}

// scenarioRecordRoundTrip: bool, blob and JSON columns of http_records read
// back as written, through both the single and batch save paths.
func scenarioRecordRoundTrip(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)

	id, err := repo.SaveRecord(ctx, makeTestRequest(1), "test", DefaultProjectUUID)
	if err != nil {
		t.Fatalf("SaveRecord: %v", err)
	}
	got, err := repo.GetRecordByUUID(ctx, id)
	if err != nil || got.Hostname != "example.com" || got.HasResponse {
		t.Fatalf("GetRecordByUUID = %+v, %v", got, err)
	}

	rec := &HTTPRecord{
		UUID: uuid.NewString(), ProjectUUID: DefaultProjectUUID,
		Scheme: "https", Hostname: "rt.example", Port: 443, Method: "POST", Path: "/x", URL: "https://rt.example/x",
		HTTPVersion: "HTTP/1.1", RequestHash: "rt-hash",
		RawRequest:  []byte("POST /x HTTP/1.1\r\nHost: rt.example\r\n\r\n\x00\xff"),
		RawResponse: []byte("HTTP/1.1 200 OK\r\n\r\nbody"), StatusCode: 200,
		HasResponse: true, IsAuthenticated: true, ChainTruncated: true,
		Remarks: []string{"jstangle:route"},
	}
	if _, err := repo.SaveRecordsBatch(ctx, []*HTTPRecord{rec}); err != nil {
		t.Fatalf("SaveRecordsBatch: %v", err)
	}
	back, err := repo.GetRecordByUUID(ctx, rec.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if !back.HasResponse || !back.IsAuthenticated || !back.ChainTruncated {
		t.Errorf("bool columns did not round-trip: has_response=%v is_authenticated=%v chain_truncated=%v",
			back.HasResponse, back.IsAuthenticated, back.ChainTruncated)
	}
	if string(back.RawRequest) != string(rec.RawRequest) {
		t.Errorf("raw_request = %q", back.RawRequest)
	}
	if !slices.Equal(back.Remarks, rec.Remarks) {
		t.Errorf("remarks = %v", back.Remarks)
	}

	recs, total, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: DefaultProjectUUID, Limit: 10}).ExecuteWithCount(ctx)
	if err != nil || total != 2 || len(recs) != 2 {
		t.Fatalf("record query = %d rows (total %d), %v", len(recs), total, err)
	}
	if err := repo.UpdateRecordAnnotations(ctx, rec.UUID, ptr(7), []string{"note"}); err != nil {
		t.Fatalf("UpdateRecordAnnotations: %v", err)
	}
}

// scenarioFindingLifecycle: save, re-detect (upsert on the project-scoped
// hash), observations, status change with its event row, and listing.
func scenarioFindingLifecycle(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	ev := &output.ResultEvent{
		ModuleID: "m",
		Info:     output.Info{Name: "M", Severity: severity.High, Confidence: severity.Firm},
		URL:      "https://f.example/a",
	}
	for _, scan := range []string{"scan-1", "scan-2", "scan-2"} {
		if err := repo.SaveFinding(ctx, ev, []string{"rec-1"}, scan, ""); err != nil {
			t.Fatalf("SaveFinding(%s): %v", scan, err)
		}
	}
	findings, total, err := repo.ListFindings(ctx, QueryFilters{ProjectUUID: DefaultProjectUUID, Limit: 10})
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("ListFindings = %d (total %d), %v; want one deduplicated finding", len(findings), total, err)
	}
	f := findings[0]
	obs, err := repo.ListFindingObservations(ctx, DefaultProjectUUID, f.ID)
	if err != nil || len(obs) != 2 {
		t.Fatalf("observations = %d, %v; want 2", len(obs), err)
	}
	if err := repo.SetFindingStatus(ctx, DefaultProjectUUID, f.ID, StatusConfirmed, "repro", "tester"); err != nil {
		t.Fatalf("SetFindingStatus: %v", err)
	}
	events, err := repo.ListFindingStatusEvents(ctx, DefaultProjectUUID, f.ID)
	if err != nil || len(events) != 1 || events[0].ToStatus != StatusConfirmed {
		t.Fatalf("status events = %+v, %v", events, err)
	}
	got, err := repo.GetFindingByID(ctx, f.ID)
	if err != nil || got.Status != StatusConfirmed || got.StatusNote != "repro" {
		t.Fatalf("finding after status change = %+v, %v", got, err)
	}
	if !slices.Equal(got.HTTPRecordUUIDs, []string{"rec-1"}) {
		t.Errorf("http_record_uuids = %v", got.HTTPRecordUUIDs)
	}
}

// scenarioScanRow: create, partial update, liveness heartbeat and read back.
func scenarioScanRow(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	scan := &Scan{UUID: uuid.NewString(), ProjectUUID: DefaultProjectUUID, Status: "running", Target: "https://s.example",
		Tags: []string{"ci"}, Plan: []byte(`{"phases":["dast"]}`)}
	if err := repo.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	sent := int64(42)
	if ok, _, err := repo.UpdateScanHeartbeat(ctx, scan.UUID, ScanHeartbeat{Phase: "dast", RequestsSent: &sent, PID: 7, Host: "h"}); err != nil || !ok {
		t.Fatalf("UpdateScanHeartbeat = %v, %v", ok, err)
	}
	scan.Status = "completed"
	scan.TotalFindings = 3
	if err := repo.UpdateScanPartial(ctx, scan); err != nil {
		t.Fatalf("UpdateScanPartial: %v", err)
	}
	got, err := repo.GetScanByUUID(ctx, scan.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" || got.TotalRequests != 42 || got.CurrentPhase != "dast" || !slices.Equal(got.Tags, []string{"ci"}) {
		t.Errorf("scan row = status %q requests %d phase %q tags %v", got.Status, got.TotalRequests, got.CurrentPhase, got.Tags)
	}
}

// scenarioBoolColumns: the remaining {{BOOL}} columns, including a TRUE
// default written by the column default rather than by the model.
func scenarioBoolColumns(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)

	sc := &Scope{ProjectUUID: DefaultProjectUUID, Name: "s", RuleType: "include", HostPattern: "*.example", Priority: 1, Enabled: true}
	if _, err := db.NewInsert().Model(sc).Exec(ctx); err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	mustExec(t, db, "INSERT INTO scopes (project_uuid, name, rule_type) VALUES (?, 'by-default', 'exclude')", DefaultProjectUUID)
	var scopes []Scope
	if err := db.NewSelect().Model(&scopes).Where("project_uuid = ?", DefaultProjectUUID).Order("id").Scan(ctx); err != nil {
		t.Fatalf("select scopes: %v", err)
	}
	if len(scopes) != 2 || !scopes[0].Enabled || !scopes[1].Enabled {
		t.Fatalf("scopes = %+v; want both enabled (one by column default)", scopes)
	}

	in := []HostObservationInput{
		{Hostname: "h.example", Port: 443, HostFacts: HostFacts{A: []string{"192.0.2.1"}}, Complete: true},
		{Hostname: "cut.example", Port: 443},
	}
	in[1].Complete = false
	in[1].A = []string{"192.0.2.2"}
	if err := repo.SaveHostObservations(ctx, DefaultProjectUUID, "scan-h", in); err != nil {
		t.Fatalf("SaveHostObservations: %v", err)
	}
	if n := scalarInt(t, db, "SELECT COUNT(*) FROM host_observations WHERE complete = ?", true); n != 1 {
		t.Errorf("complete observations = %d, want 1", n)
	}
	facts, err := repo.LookupHostObservation(ctx, DefaultProjectUUID, "scan-h", "h.example", 443)
	if err != nil || !slices.Equal(facts.A, []string{"192.0.2.1"}) {
		t.Errorf("LookupHostObservation = %+v, %v", facts, err)
	}
}

// scenarioProjectIsolation: rows written under one project never appear in
// another's reads.
func scenarioProjectIsolation(t *testing.T, db *DB) {
	ctx := context.Background()
	repo := NewRepository(db)
	other := &Project{UUID: uuid.NewString(), Name: "other-" + uuid.NewString()[:8]}
	if err := repo.CreateProject(ctx, other); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	for i, project := range []string{DefaultProjectUUID, other.UUID} {
		if _, err := repo.SaveRecord(ctx, makeTestRequest(10+i), "test", project); err != nil {
			t.Fatal(err)
		}
		ev := &output.ResultEvent{
			ModuleID: "iso",
			Info:     output.Info{Name: "Iso", Severity: severity.Low, Confidence: severity.Firm},
			URL:      "https://iso.example/",
		}
		// The same finding in both projects: dedup is per project.
		if err := repo.SaveFinding(ctx, ev, nil, fmt.Sprintf("scan-%d", i), project); err != nil {
			t.Fatal(err)
		}
	}
	for _, project := range []string{DefaultProjectUUID, other.UUID} {
		_, total, err := NewQueryBuilder(db, QueryFilters{ProjectUUID: project, Limit: 10}).ExecuteWithCount(ctx)
		if err != nil || total != 1 {
			t.Errorf("project %s records = %d, %v; want 1", project, total, err)
		}
		_, total, err = repo.ListFindings(ctx, QueryFilters{ProjectUUID: project, Limit: 10})
		if err != nil || total != 1 {
			t.Errorf("project %s findings = %d, %v; want 1", project, total, err)
		}
	}
}

// TestPg_LegacyBoolColumnsConverted: a Postgres store created before the
// per-dialect templates holds bool columns as INTEGER. The readiness check
// reports them, `db migrate` (CreateSchema) converts them in place keeping
// every value and the default, and bool writes work afterwards.
func TestPg_LegacyBoolColumnsConverted(t *testing.T) {
	db := openPGTestDB(t)
	ctx := context.Background()

	// Rewind to the legacy shape: chain_truncated and is_authenticated as
	// INTEGER (what the string-rewriting DDL left), with rows in both states.
	for _, col := range []string{"chain_truncated", "is_authenticated"} {
		mustExec(t, db, "ALTER TABLE http_records ALTER COLUMN "+col+" DROP DEFAULT")
		mustExec(t, db, "ALTER TABLE http_records ALTER COLUMN "+col+" TYPE INTEGER USING (CASE WHEN "+col+" THEN 1 ELSE 0 END)")
		mustExec(t, db, "ALTER TABLE http_records ALTER COLUMN "+col+" SET DEFAULT 0")
	}
	insert := `INSERT INTO http_records (uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, chain_truncated, is_authenticated)
		VALUES (?, ?, 'https', 'l.example', 443, 'GET', '/', 'https://l.example/', 'HTTP/1.1', ?, ?, ?)`
	mustExec(t, db, insert, "legacy-1", DefaultProjectUUID, "h1", 1, 0)
	mustExec(t, db, insert, "legacy-0", DefaultProjectUUID, "h0", 0, 1)

	// The failure this migration exists for: a bool write into INTEGER.
	broken := &HTTPRecord{UUID: uuid.NewString(), ProjectUUID: DefaultProjectUUID, Scheme: "https", Hostname: "l.example",
		Port: 443, Method: "GET", Path: "/b", URL: "https://l.example/b", HTTPVersion: "HTTP/1.1", RequestHash: "hb",
		ChainTruncated: true}
	if _, err := NewRepository(db).SaveRecordsBatch(ctx, []*HTTPRecord{broken}); err == nil {
		t.Fatal("bool write into a legacy INTEGER column succeeded; the fixture no longer models the bug")
	}

	gaps := db.schemaGaps(ctx)
	if len(gaps) != 2 || !strings.Contains(strings.Join(gaps, ","), "http_records.chain_truncated is integer") {
		t.Fatalf("gaps on a legacy store = %v; want both integer bool columns", gaps)
	}

	res, err := db.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.AlreadyCurrent || len(res.Applied) != 2 {
		t.Errorf("Migrate result = %+v; want the two conversions applied", res)
	}
	if legacy, err := db.legacyBoolColumns(ctx); err != nil || len(legacy) != 0 {
		t.Fatalf("after migrate legacy columns = %v, %v", legacy, err)
	}

	var truncated, authed bool
	for _, tc := range []struct {
		uuid            string
		truncated, auth bool
	}{{"legacy-1", true, false}, {"legacy-0", false, true}} {
		if err := db.QueryRowContext(ctx, "SELECT chain_truncated, is_authenticated FROM http_records WHERE uuid = ?", tc.uuid).
			Scan(&truncated, &authed); err != nil {
			t.Fatal(err)
		}
		if truncated != tc.truncated || authed != tc.auth {
			t.Errorf("%s converted to chain_truncated=%v is_authenticated=%v", tc.uuid, truncated, authed)
		}
	}
	var def string
	if err := db.QueryRowContext(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'http_records' AND column_name = 'chain_truncated'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(def, "false") {
		t.Errorf("chain_truncated default after conversion = %q, want false", def)
	}

	// The write that failed on the legacy store.
	rec := &HTTPRecord{UUID: uuid.NewString(), ProjectUUID: DefaultProjectUUID, Scheme: "https", Hostname: "l.example",
		Port: 443, Method: "GET", Path: "/n", URL: "https://l.example/n", HTTPVersion: "HTTP/1.1", RequestHash: "hn",
		ChainTruncated: true}
	if _, err := NewRepository(db).SaveRecordsBatch(ctx, []*HTTPRecord{rec}); err != nil {
		t.Fatalf("bool write after conversion: %v", err)
	}

	// Converting is idempotent: the next CreateSchema finds nothing to do.
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }
