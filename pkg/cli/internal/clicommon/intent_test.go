package clicommon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

// isolateDBState gives a test its own HOME (no user config is discovered) and
// restores the opener's package state afterwards.
func isolateDBState(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	t.Cleanup(func() {
		ResetDBCache()
		Policy = OpenPolicy{Intent: IntentWrite}
	})
	ResetDBCache()
}

// writeConfig writes a config file that only sets auto_migrate_on_read.
func writeConfig(t *testing.T, autoMigrate bool) string {
	t.Helper()
	v := "false"
	if autoMigrate {
		v = "true"
	}
	path := filepath.Join(t.TempDir(), "vigolium-configs.yaml")
	if err := os.WriteFile(path, []byte("database:\n  auto_migrate_on_read: "+v+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// v1Store builds a store that is one schema version behind: current tables,
// but schema_meta in its v1 shape.
func v1Store(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v1.sqlite")
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.EnsureSchemaReady(ctx); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"DROP TABLE schema_meta",
		"CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, version INTEGER NOT NULL DEFAULT 0)",
		"INSERT INTO schema_meta (id, version) VALUES (1, 1)",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	_ = db.Close()
	return path
}

func TestGetDBFor_ReadIntentOpensQueryOnlyPool(t *testing.T) {
	isolateDBState(t)
	path := filepath.Join(t.TempDir(), "fresh", "store.sqlite")

	// A missing (unpinned) store is initialized through a writer, then read.
	db, err := GetDBFor(IntentRead, writeConfig(t, true), path)
	if err != nil {
		t.Fatalf("GetDBFor(read) on a fresh path: %v", err)
	}
	if !db.IsReader() {
		t.Fatal("read intent did not open the read pool")
	}
	if err := db.CheckSchema(context.Background()); err != nil {
		t.Errorf("fresh store not initialized for the reader: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "DELETE FROM findings"); err == nil {
		t.Error("read pool accepted a write")
	}

	// A write intent in the same process supersedes the reader with a writer.
	w, err := GetDBFor(IntentWrite, "", path)
	if err != nil {
		t.Fatalf("GetDBFor(write): %v", err)
	}
	if w.IsReader() || w == db {
		t.Fatal("write intent reused the read pool")
	}
	// And the writer then serves reads.
	if again, _ := GetDBFor(IntentRead, "", path); again != w {
		t.Error("a cached writer should serve a later read")
	}
}

func TestGetDBFor_ReadIntentOutdatedStore(t *testing.T) {
	t.Run("auto_migrate_on_read false refuses with schema_outdated", func(t *testing.T) {
		isolateDBState(t)
		path := v1Store(t)
		_, err := GetDBFor(IntentRead, writeConfig(t, false), path)
		if !errors.Is(err, database.ErrSchemaOutdated) {
			t.Fatalf("err = %v, want ErrSchemaOutdated", err)
		}
		var outdated *database.SchemaOutdatedError
		if !errors.As(err, &outdated) {
			t.Fatalf("err %T is not *SchemaOutdatedError", err)
		}
	})
	t.Run("auto_migrate_on_read true migrates through a writer", func(t *testing.T) {
		isolateDBState(t)
		path := v1Store(t)
		db, err := GetDBFor(IntentRead, writeConfig(t, true), path)
		if err != nil {
			t.Fatalf("GetDBFor(read): %v", err)
		}
		info, err := db.SchemaInfo(context.Background())
		if err != nil || info.Version != database.CurrentSchemaVersion() {
			t.Fatalf("after auto-migrate: %+v, %v", info, err)
		}
	})
}

func TestGetDBFor_TooNewStore(t *testing.T) {
	isolateDBState(t)
	path := v1Store(t)
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(),
		"UPDATE schema_meta SET version = 99, min_reader_version = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Readable (additive), so a read works...
	r, err := GetDBFor(IntentRead, writeConfig(t, true), path)
	if err != nil {
		t.Fatalf("read of a readable newer store: %v", err)
	}
	_ = r
	ResetDBCache()
	// ...and a write is refused with schema_too_new.
	if _, err := GetDBFor(IntentWrite, "", path); !errors.Is(err, database.ErrSchemaTooNew) {
		t.Fatalf("write of a newer store = %v, want ErrSchemaTooNew", err)
	}
}

func TestGetDBFor_ReadOnlyForcesEvidence(t *testing.T) {
	isolateDBState(t)
	path := filepath.Join(t.TempDir(), "evidence.sqlite")
	if _, err := GetDBFor(IntentWrite, "", path); err != nil {
		t.Fatal(err)
	}
	ResetDBCache()

	Policy.ReadOnly = true
	db, err := GetDBFor(IntentWrite, "", path)
	if err != nil {
		t.Fatalf("evidence open: %v", err)
	}
	if db.IsReader() {
		t.Error("--read-only must open the evidence handle, not the read pool")
	}
	if _, err := db.ExecContext(context.Background(), "DELETE FROM findings"); err == nil {
		t.Error("evidence handle accepted a write")
	}
}

func TestOpenIntentServes(t *testing.T) {
	cases := []struct {
		have, want OpenIntent
		ok         bool
	}{
		{IntentWrite, IntentRead, true},
		{IntentWrite, IntentWrite, true},
		{IntentRead, IntentRead, true},
		{IntentRead, IntentWrite, false},
		{IntentEvidence, IntentWrite, true},
	}
	for _, c := range cases {
		if got := c.have.serves(c.want); got != c.ok {
			t.Errorf("%v.serves(%v) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}
