package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// newEmptyDB opens an in-memory SQLite *DB WITHOUT running CreateSchema, so the
// caller controls schema setup (e.g. to simulate a database left behind by an
// older binary version).
func newEmptyDB(t *testing.T) *DB {
	t.Helper()

	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// :memory: databases are per-connection — pin to one so every statement
	// sees the same database.
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)

	db := &DB{DB: bun.NewDB(sqldb, sqlitedialect.New()), driver: "sqlite"}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func columnExists(t *testing.T, db *DB, table, column string) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&n); err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	return n > 0
}

func indexExists(t *testing.T, db *DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?", name).Scan(&n); err != nil {
		t.Fatalf("sqlite_master lookup: %v", err)
	}
	return n > 0
}

// TestCreateSchema_HealsExistingDBMissingNormHashColumn reproduces a production
// incident: v0.1.35 added http_records.response_norm_hash together with an index
// on it (idx_records_norm_hash). On a *pre-existing* database CreateSchema ran
// the index-creation loop before the column-add migration, so CREATE INDEX hit a
// column that did not exist yet, errored, and aborted CreateSchema entirely —
// which left the server's repo nil and broke a swathe of endpoints.
//
// The invariant this guards: every column referenced by an index must be created
// (in the base CREATE TABLE or by an addColumnIfNotExists migration) BEFORE the
// index-creation loop runs. Running CreateSchema against a database that predates
// the column must succeed and add both the column and its index.
//
// Without the correct ordering this test fails at the second CreateSchema call.
func TestCreateSchema_HealsExistingDBMissingNormHashColumn(t *testing.T) {
	ctx := context.Background()
	db := newEmptyDB(t)

	// Build the current schema, then strip the column + index so the database
	// looks like one created by an older binary that never knew about them.
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("initial CreateSchema: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_records_norm_hash"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE http_records DROP COLUMN response_norm_hash"); err != nil {
		t.Fatalf("drop column to simulate legacy DB: %v", err)
	}
	if columnExists(t, db, "http_records", "response_norm_hash") {
		t.Fatal("setup failed: response_norm_hash still present after DROP COLUMN")
	}

	// Re-run schema init against the legacy-shaped database. This is the
	// regression: with indexes created before column migrations it returns an
	// error here; with the correct ordering it heals the schema.
	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema on legacy DB must succeed, got: %v", err)
	}

	if !columnExists(t, db, "http_records", "response_norm_hash") {
		t.Error("response_norm_hash column was not re-added by CreateSchema")
	}
	if !indexExists(t, db, "idx_records_norm_hash") {
		t.Error("idx_records_norm_hash index was not created by CreateSchema")
	}
}

// TestCreateSchema_AddsMigrationLessScansColumns guards a second production
// incident found on the demo (SQLite) host: scans.source_type and
// scans.http_record_uuid exist in the scans CREATE TABLE but had no
// addColumnIfNotExists migration, so databases that predated those columns hit
// "no such column: sc.source_type" on /api/scans. Any column the code selects
// must also have a migration so existing databases gain it on upgrade.
func TestCreateSchema_AddsMigrationLessScansColumns(t *testing.T) {
	ctx := context.Background()
	db := newEmptyDB(t)

	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("initial CreateSchema: %v", err)
	}

	// Strip the columns to mimic a scans table created by an older binary.
	for _, col := range []string{"source_type", "http_record_uuid"} {
		if _, err := db.ExecContext(ctx, "ALTER TABLE scans DROP COLUMN "+col); err != nil {
			t.Fatalf("drop scans.%s: %v", col, err)
		}
		if columnExists(t, db, "scans", col) {
			t.Fatalf("setup failed: scans.%s still present after drop", col)
		}
	}

	if err := db.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema on legacy DB must succeed, got: %v", err)
	}

	for _, col := range []string{"source_type", "http_record_uuid"} {
		if !columnExists(t, db, "scans", col) {
			t.Errorf("scans.%s was not re-added by CreateSchema (missing migration)", col)
		}
	}
}

// TestCreateSchema_UpgradeFromGenesisBaseline is the general guard against the
// whole class of schema-upgrade bugs. It builds a database that looks like one
// created by an older binary — every table holds only its frozen "genesis"
// columns (testdata/schema_genesis_baseline.json: the columns that predate any
// addColumnIfNotExists migration) — then runs CreateSchema and requires the
// result to match a freshly created schema.
//
// It catches both production incidents automatically:
//   - a column added to a CREATE TABLE with no migration, so existing databases
//     never gain it (e.g. scans.source_type); and
//   - an index created before the column it references is added, which aborts
//     CreateSchema entirely (e.g. idx_records_norm_hash → response_norm_hash).
//
// IMPORTANT: when you add a column to a CREATE TABLE in db.go, add a matching
// addColumnIfNotExists migration for it — do NOT add it to the baseline fixture.
// A fresh DB would otherwise have the column while an upgraded DB would not, and
// this test fails (which is the point).
func TestCreateSchema_UpgradeFromGenesisBaseline(t *testing.T) {
	ctx := context.Background()

	raw, err := os.ReadFile(filepath.Join("testdata", "schema_genesis_baseline.json"))
	if err != nil {
		t.Fatalf("read baseline fixture: %v", err)
	}
	var baseline struct {
		Tables map[string][]string `json:"tables"`
	}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatalf("parse baseline fixture: %v", err)
	}
	if len(baseline.Tables) == 0 {
		t.Fatal("baseline fixture has no tables")
	}

	// Build the genesis-shaped database. Typeless columns are fine on SQLite —
	// the test only compares column presence, not types.
	legacy := newEmptyDB(t)
	for table, cols := range baseline.Tables {
		if len(cols) == 0 {
			continue
		}
		stmt := fmt.Sprintf("CREATE TABLE %s (%s)", table, strings.Join(cols, ", "))
		if _, err := legacy.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("create genesis table %s: %v", table, err)
		}
	}

	// The upgrade must run to completion (guards the index-before-column bug —
	// CreateSchema returns an error if an index is built on a missing column).
	if err := legacy.CreateSchema(ctx); err != nil {
		t.Fatalf("CreateSchema upgrading a genesis database must succeed, got: %v", err)
	}

	// Every column a fresh schema has must also exist after the upgrade
	// (guards missing migrations).
	fresh := newTestDB(t)
	for table := range baseline.Tables {
		for _, col := range pragmaColumns(t, fresh, table) {
			if !columnExists(t, legacy, table, col) {
				t.Errorf("%s.%s exists in a fresh schema but is missing after upgrading a genesis DB — add an addColumnIfNotExists migration for it in CreateSchema", table, col)
			}
		}
	}
}

// tableColumns returns the column names of a table on an SQLite *DB.
func pragmaColumns(t *testing.T, db *DB, table string) []string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	return cols
}

// TestCreateSchema_Idempotent runs CreateSchema repeatedly on the same database
// and requires every run to succeed. A migration that is not safe to re-apply
// (a non-IF-NOT-EXISTS DDL, or an index built before its column) surfaces as an
// error on the second pass.
func TestCreateSchema_Idempotent(t *testing.T) {
	ctx := context.Background()
	db := newEmptyDB(t)

	for i := 0; i < 3; i++ {
		if err := db.CreateSchema(ctx); err != nil {
			t.Fatalf("CreateSchema run %d failed: %v", i+1, err)
		}
	}

	// A representative index whose column (response_norm_hash) is migration-added
	// must exist after repeated runs.
	if !indexExists(t, db, "idx_records_norm_hash") {
		t.Error("idx_records_norm_hash missing after repeated CreateSchema runs")
	}
}
