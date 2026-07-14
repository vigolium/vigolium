package cli

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
)

func sqliteDBConfig(path string) *config.DatabaseConfig {
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	return cfg
}

// TestInitServerDatabase_FreshPathSucceeds is the happy path: a brand-new SQLite
// file opens, its schema is created, and both the db handle and repository come
// back non-nil.
func TestInitServerDatabase_FreshPathSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.sqlite")

	db, repo := initServerDatabase(sqliteDBConfig(path), true)
	if db == nil || repo == nil {
		t.Fatalf("fresh database should initialize; got db!=nil=%v repo!=nil=%v", db != nil, repo != nil)
	}
	t.Cleanup(func() { _ = db.Close() })
}

// TestInitServerDatabase_SchemaFailureDegradesToNoDB is the regression guard for
// the reported REST panic. When the connection opens but CreateSchema fails
// (here: a pre-existing findings table from an incompatible schema, so an index
// build errors), initServerDatabase must degrade to (nil, nil) — NOT return a
// live db with a nil repo, the pairing that made every repo-backed handler
// nil-pointer panic with HTTP 500.
func TestInitServerDatabase_SchemaFailureDegradesToNoDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")

	// Seed a valid, writable DB whose findings table predates the current columns,
	// so NewDB (open + ping) succeeds but CreateSchema's index build fails.
	seed, err := sql.Open(sqliteshim.ShimName, path)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if _, err := seed.Exec(`CREATE TABLE findings (project_uuid TEXT, finding_hash TEXT)`); err != nil {
		t.Fatalf("seed legacy findings table: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	db, repo := initServerDatabase(sqliteDBConfig(path), true)
	if db != nil {
		_ = db.Close()
		t.Fatalf("schema failure must degrade to a nil db; got a live handle (repo-backed handlers would panic)")
	}
	if repo != nil {
		t.Fatalf("schema failure must degrade to a nil repo; got %v", repo)
	}
}

// TestInitServerDatabase_OpenFailureDegradesToNoDB confirms the older open-failure
// path (a corrupt file that fails NewDB's ping) also yields (nil, nil).
func TestInitServerDatabase_OpenFailureDegradesToNoDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.sqlite")
	if err := os.WriteFile(path, []byte("this is not a sqlite database\n"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	db, repo := initServerDatabase(sqliteDBConfig(path), true)
	if db != nil {
		_ = db.Close()
		t.Fatalf("open failure must degrade to a nil db")
	}
	if repo != nil {
		t.Fatalf("open failure must degrade to a nil repo; got %v", repo)
	}
}
