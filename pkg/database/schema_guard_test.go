package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
)

// currentFileDB returns a file-backed store with the current schema, closed.
func currentFileDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.sqlite")
	db := openDBFile(t, path, false)
	if err := db.CreateSchema(context.Background()); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	_ = db.Close()
	return path
}

// openReaderFile opens the read-intent pool on path.
func openReaderFile(t *testing.T, path string) *DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = path
	cfg.ReadIntent = true
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// stampSchemaMeta rewrites schema_meta directly, the way a newer binary would
// have left it.
func stampSchemaMeta(t *testing.T, path string, version, minReader int) {
	t.Helper()
	db := openDBFile(t, path, false)
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(),
		"UPDATE schema_meta SET version = ?, min_reader_version = ?, written_by = 'v9.9.9' WHERE id = 1",
		version, minReader); err != nil {
		t.Fatalf("stamp schema_meta: %v", err)
	}
}

func TestSchemaInfo_FreshStoreStampsGuardColumns(t *testing.T) {
	SetBinaryVersion("v-test")
	path := currentFileDB(t)
	db := openReaderFile(t, path)

	info, err := db.SchemaInfo(context.Background())
	if err != nil {
		t.Fatalf("SchemaInfo: %v", err)
	}
	if info.Version != currentSchemaVersion || info.MinReaderVersion != minReaderVersion {
		t.Fatalf("info = %+v, want version %d min_reader %d", info, currentSchemaVersion, minReaderVersion)
	}
	if info.WrittenBy != "v-test" || info.UpdatedAt == "" {
		t.Errorf("written_by/updated_at not stamped: %+v", info)
	}
}

// A v1 store (schema_meta without the guard columns) migrates additively: the
// backfilled min_reader_version is 1 and the version moves to 2.
func TestSchemaGuard_V1StoreMigratesAdditively(t *testing.T) {
	path := currentFileDB(t)
	db := openDBFile(t, path, false)
	ctx := context.Background()
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

	r := openReaderFile(t, path)
	info, err := r.SchemaInfo(ctx)
	if err != nil || info.Version != 1 || info.MinReaderVersion != 1 {
		t.Fatalf("v1 SchemaInfo = %+v, %v; want version 1, min_reader 1", info, err)
	}
	if err := r.CheckSchema(ctx); !errors.Is(err, ErrSchemaOutdated) {
		t.Fatalf("CheckSchema on v1 store = %v, want ErrSchemaOutdated", err)
	}
	var coded interface{ Code() apicontract.ErrorCode }
	if err := r.CheckSchema(ctx); !errors.As(err, &coded) || coded.Code() != apicontract.CodeSchemaOutdated {
		t.Errorf("outdated error is not coded schema_outdated: %v", err)
	}

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	res, err := w.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.FromVersion != 1 || res.ToVersion != currentSchemaVersion || res.MinReaderVersion != minReaderVersion || res.AlreadyCurrent {
		t.Errorf("Migrate result = %+v", res)
	}
	if len(res.Applied) == 0 {
		t.Error("Migrate reported no applied steps on a v1 store")
	}
	if err := r.CheckSchema(ctx); err != nil {
		t.Errorf("CheckSchema after migrate = %v, want nil", err)
	}
	again, err := w.Migrate(ctx)
	if err != nil || !again.AlreadyCurrent || len(again.Applied) != 0 {
		t.Errorf("second Migrate = %+v, %v; want already current", again, err)
	}
}

// version=99, min_reader=99: this binary can neither read nor write it.
func TestSchemaGuard_UnreadableNewerStoreRefused(t *testing.T) {
	path := currentFileDB(t)
	stampSchemaMeta(t, path, 99, 99)
	ctx := context.Background()

	r := openReaderFile(t, path)
	err := r.CheckSchema(ctx)
	var tooNew *SchemaTooNewError
	if !errors.As(err, &tooNew) || tooNew.Write {
		t.Fatalf("CheckSchema = %v, want read-refusing SchemaTooNewError", err)
	}
	if tooNew.Code() != apicontract.CodeSchemaTooNew || tooNew.WrittenBy != "v9.9.9" {
		t.Errorf("error = %+v", tooNew)
	}

	ro := openDBFile(t, path, true)
	defer func() { _ = ro.Close() }()
	if err := ro.EnsureSchemaCurrent(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Errorf("--read-only open = %v, want ErrSchemaTooNew", err)
	}
}

// version=99, min_reader=1: readable (additive), but writes are refused and the
// stored version is never lowered.
func TestSchemaGuard_ReadableNewerStoreRefusesWrites(t *testing.T) {
	path := currentFileDB(t)
	stampSchemaMeta(t, path, 99, 1)
	ctx := context.Background()

	r := openReaderFile(t, path)
	if err := r.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema on a readable newer store = %v, want nil", err)
	}
	var n int
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&n); err != nil {
		t.Fatalf("read: %v", err)
	}

	w := openDBFile(t, path, false)
	defer func() { _ = w.Close() }()
	for name, fn := range map[string]func(context.Context) error{
		"EnsureSchemaReady":   w.EnsureSchemaReady,
		"EnsureSchemaCurrent": w.EnsureSchemaCurrent,
		"CreateSchema":        w.CreateSchema,
		"Migrate":             func(ctx context.Context) error { _, err := w.Migrate(ctx); return err },
	} {
		err := fn(ctx)
		var tooNew *SchemaTooNewError
		if !errors.As(err, &tooNew) || !tooNew.Write {
			t.Errorf("%s = %v, want write-refusing SchemaTooNewError", name, err)
		}
	}
	if v := w.schemaVersion(ctx); v != 99 {
		t.Errorf("schema version = %d after refused writes, want 99", v)
	}
}

func TestCheckSchema_EmptyFileNotInitialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.sqlite")
	w := openDBFile(t, path, false) // creates the file, no tables
	_ = w.Close()

	r := openReaderFile(t, path)
	if err := r.CheckSchema(context.Background()); !errors.Is(err, ErrSchemaNotInitialized) {
		t.Fatalf("CheckSchema on empty file = %v, want ErrSchemaNotInitialized", err)
	}
}
