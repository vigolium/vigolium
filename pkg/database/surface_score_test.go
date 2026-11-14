package database

import (
	"context"
	"fmt"
	"testing"
)

// TestCreateSchemaAddsSurfaceScoreColumn covers a fresh database: the column must
// be present straight from the CREATE TABLE.
func TestCreateSchemaAddsSurfaceScoreColumn(t *testing.T) {
	db := newTestDB(t)
	if !columnExists(t, db, "http_records", "surface_score") {
		t.Fatal("fresh schema is missing http_records.surface_score")
	}
}

// TestSurfaceScoreMigratesExistingDatabase is the seamless-migration contract:
// an existing database created before surface_score existed, carrying rows, must
// gain the column on the next open with its data intact and the new column
// defaulting to 0.
//
// It deliberately does NOT set schema_meta. The column migration is ungated by
// design (CreateSchema runs the cheap idempotent DDL on every open), so this also
// proves the column arrives without bumping currentSchemaVersion — a bump would
// re-run the O(rows) backfills on every existing database.
func TestSurfaceScoreMigratesExistingDatabase(t *testing.T) {
	ctx := context.Background()
	db := newEmptyDB(t)

	// Build the pre-surface_score shape by creating the current schema and
	// removing the column again. Deriving the fixture from db.go's own DDL is
	// what keeps it honest: a hand-copied legacy CREATE TABLE drifts silently the
	// first time an unrelated column is added.
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema: %v", err)
	}
	// The index has to go first — SQLite refuses to drop a column an index
	// references. Dropping both is also what makes this a faithful fixture: a
	// pre-surface_score database has neither.
	for _, idx := range []string{"idx_records_project_surface_score", "idx_records_project_risk_order"} {
		if _, err := db.ExecContext(ctx, "DROP INDEX IF EXISTS "+idx); err != nil {
			t.Fatalf("drop surface_score index %s: %v", idx, err)
		}
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE http_records DROP COLUMN surface_score"); err != nil {
		t.Fatalf("drop surface_score to build the legacy fixture: %v", err)
	}
	if columnExists(t, db, "http_records", "surface_score") {
		t.Fatal("legacy fixture still has surface_score; the fixture is not testing a migration")
	}
	for i := 0; i < 3; i++ {
		_, err := db.ExecContext(ctx, `INSERT INTO http_records
			(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash, risk_score)
			VALUES (?, ?, 'https', 'example.com', 443, 'GET', ?, ?, 'HTTP/1.1', ?, ?)`,
			fmt.Sprintf("legacy-%d", i), DefaultProjectUUID,
			fmt.Sprintf("/p%d", i), fmt.Sprintf("https://example.com/p%d", i),
			fmt.Sprintf("hash-%d", i), 42)
		if err != nil {
			t.Fatalf("seed legacy row %d: %v", i, err)
		}
	}

	// Open as the current binary would.
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema on legacy database: %v", err)
	}

	if !columnExists(t, db, "http_records", "surface_score") {
		t.Fatal("surface_score was not added to the existing http_records table")
	}

	// Pre-existing rows survive, keep their data, and read 0 for the new column.
	var count, zeroSurface, riskPreserved int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*),
			SUM(CASE WHEN surface_score = 0 THEN 1 ELSE 0 END),
			SUM(CASE WHEN risk_score = 42 THEN 1 ELSE 0 END)
		FROM http_records`).Scan(&count, &zeroSurface, &riskPreserved); err != nil {
		t.Fatalf("query migrated rows: %v", err)
	}
	if count != 3 {
		t.Errorf("row count after migration = %d, want 3 (existing data must survive)", count)
	}
	if zeroSurface != 3 {
		t.Errorf("%d of 3 rows have surface_score = 0, want 3 (un-scored is the correct floor)", zeroSurface)
	}
	if riskPreserved != 3 {
		t.Errorf("%d of 3 rows kept risk_score = 42, want 3", riskPreserved)
	}

	// The new column is writable and readable through the model.
	repo := NewRepository(db)
	if err := repo.UpdateSurfaceScores(ctx, map[string]int{"legacy-1": 80}); err != nil {
		t.Fatalf("UpdateSurfaceScores on migrated database: %v", err)
	}
	rec, err := repo.GetRecordByUUID(ctx, "legacy-1")
	if err != nil {
		t.Fatalf("GetRecordByUUID: %v", err)
	}
	if rec.SurfaceScore != 80 {
		t.Errorf("SurfaceScore = %d, want 80", rec.SurfaceScore)
	}
	if rec.RiskScore != 42 {
		t.Errorf("RiskScore = %d, want 42 — writing surface_score must not disturb risk_score", rec.RiskScore)
	}
}

// TestCreateSchemaIsRepeatable guards that a second open does not fail on the
// already-present column (addColumnIfNotExists swallows the duplicate error).
func TestCreateSchemaIsRepeatable(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	for i := 0; i < 3; i++ {
		if err := db.CreateSchema(ctx); err != nil {
			t.Fatalf("CreateSchema open %d: %v", i+2, err)
		}
	}
	if !columnExists(t, db, "http_records", "surface_score") {
		t.Fatal("surface_score disappeared across repeated opens")
	}
}

// TestUpdateSurfaceScoresIsIndependentOfRiskScore guards the whole reason the
// two live in separate columns: neither writer may disturb the other's value.
func TestUpdateSurfaceScoresIsIndependentOfRiskScore(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)

	rec := &HTTPRecord{
		UUID: "rec-1", ProjectUUID: DefaultProjectUUID, Scheme: "https",
		Hostname: "example.com", Port: 443, Method: "GET", Path: "/",
		URL: "https://example.com/", HTTPVersion: "HTTP/1.1", RequestHash: "h1",
	}
	if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
		t.Fatalf("insert record: %v", err)
	}

	if err := repo.UpdateRiskScores(ctx, map[string]int{"rec-1": 77}); err != nil {
		t.Fatalf("UpdateRiskScores: %v", err)
	}
	if err := repo.UpdateSurfaceScores(ctx, map[string]int{"rec-1": 60}); err != nil {
		t.Fatalf("UpdateSurfaceScores: %v", err)
	}

	got, err := repo.GetRecordByUUID(ctx, "rec-1")
	if err != nil {
		t.Fatalf("GetRecordByUUID: %v", err)
	}
	if got.RiskScore != 77 {
		t.Errorf("RiskScore = %d, want 77 — the surface write clobbered it", got.RiskScore)
	}
	if got.SurfaceScore != 60 {
		t.Errorf("SurfaceScore = %d, want 60", got.SurfaceScore)
	}

	// And the reverse order.
	if err := repo.UpdateRiskScores(ctx, map[string]int{"rec-1": 11}); err != nil {
		t.Fatalf("UpdateRiskScores: %v", err)
	}
	got, err = repo.GetRecordByUUID(ctx, "rec-1")
	if err != nil {
		t.Fatalf("GetRecordByUUID: %v", err)
	}
	if got.SurfaceScore != 60 {
		t.Errorf("SurfaceScore = %d, want 60 — the risk write clobbered it", got.SurfaceScore)
	}
}

// TestMinSurfaceScoreFilter covers the read path the CLI --min-surface flag and
// the REST min_surface query parameter both resolve through.
func TestMinSurfaceScoreFilter(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	repo := NewRepository(db)

	scores := map[string]int{"low": 20, "mid": 60, "high": 100}
	for uuid := range scores {
		rec := &HTTPRecord{
			UUID: uuid, ProjectUUID: DefaultProjectUUID, Scheme: "https",
			Hostname: "example.com", Port: 443, Method: "GET", Path: "/" + uuid,
			URL: "https://example.com/" + uuid, HTTPVersion: "HTTP/1.1", RequestHash: "h-" + uuid,
		}
		if _, err := db.NewInsert().Model(rec).Exec(ctx); err != nil {
			t.Fatalf("insert %s: %v", uuid, err)
		}
	}
	if err := repo.UpdateSurfaceScores(ctx, scores); err != nil {
		t.Fatalf("UpdateSurfaceScores: %v", err)
	}

	tests := []struct {
		min  int
		want int
	}{
		{0, 3}, // unset filter returns everything
		{20, 3},
		{60, 2},
		{100, 1},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("min=%d", tt.min), func(t *testing.T) {
			qb := NewQueryBuilder(db, QueryFilters{
				ProjectUUID:     DefaultProjectUUID,
				MinSurfaceScore: tt.min,
				Limit:           100,
			})
			records, err := qb.Execute(ctx)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if len(records) != tt.want {
				t.Errorf("min-surface %d returned %d records, want %d", tt.min, len(records), tt.want)
			}
		})
	}
}
