package database

import (
	"slices"
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

// TestExpectedSchemaObjectsCoversDDL guards the parser that derives the expected
// object set from the DDL. A statement it cannot read would silently shrink that
// set, which is the one way this check could start accepting an incomplete
// schema — and the reason the set is parsed rather than hand-listed.
func TestExpectedSchemaObjectsCoversDDL(t *testing.T) {
	names := expectedSchemaObjects()
	if want := len(schemaTables) + len(schemaIndexes); len(names.core) != want {
		t.Errorf("parsed %d core object names from %d DDL statements — one did not match ddlObjectPattern",
			len(names.core), want)
	}
	if want := len(recordSecondaryIndexes); len(names.deferrable) != want {
		t.Errorf("parsed %d deferrable index names from %d DDL statements — one did not match ddlObjectPattern",
			len(names.deferrable), want)
	}

	// Spot-check each list, so a regex change that captured an index's TABLE name
	// instead of the index's own name is caught.
	for _, want := range []string{"http_records", "findings", "schema_meta", "idx_findings_project_severity"} {
		if !slices.Contains(names.core, want) {
			t.Errorf("expected core object %q missing from the parsed set", want)
		}
	}
	// idx_records_dedup is the covering index findDuplicateRecord needs, and the
	// one the first version of this check silently omitted by parsing only two of
	// CreateSchema's three DDL lists.
	if !slices.Contains(names.deferrable, "idx_records_dedup") {
		t.Errorf("expected deferrable index idx_records_dedup missing from the parsed set")
	}
}

// TestSchemaReadyOnCurrentDatabase is the fast path: a database CreateSchema
// just finished with must need no further DDL.
func TestSchemaReadyOnCurrentDatabase(t *testing.T) {
	db, _ := tempSchemaDB(t)

	if gaps := db.schemaGaps(t.Context()); len(gaps) != 0 {
		t.Fatalf("a database CreateSchema just built reports gaps: %v", gaps)
	}
	if err := db.EnsureSchemaReady(t.Context()); err != nil {
		t.Fatalf("EnsureSchemaReady: %v", err)
	}
}

// TestSchemaReadyOnFreshFile covers the stateless case: an empty file has no
// catalog to check, so readiness must report a gap and fall through to the full
// CreateSchema rather than reporting itself ready.
func TestSchemaReadyOnFreshFile(t *testing.T) {
	cfg := writableConfig(t.TempDir() + "/fresh.sqlite")
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if gaps := db.schemaGaps(t.Context()); len(gaps) == 0 {
		t.Fatal("schemaGaps reported an empty file as ready")
	}
	if err := db.EnsureSchemaReady(t.Context()); err != nil {
		t.Fatalf("EnsureSchemaReady on a fresh file: %v", err)
	}
	if !db.HasVigoliumSchema(t.Context()) {
		t.Fatal("EnsureSchemaReady left a fresh file without the schema")
	}
}

// TestSchemaReadyDetectsMissingObjects is the correctness guard: a missing
// TABLE or a missing UNIQUE INDEX must not pass, even though every migrated
// column is present. EnsureSchemaCurrent, which checks columns only, accepts all
// of these — which is why it is not what the scan entry points use.
//
// idx_records_dedup is here because it lives in recordSecondaryIndexes, the
// third DDL list CreateSchema applies; the first version of this check parsed
// only the other two and reported a store missing it as ready.
func TestSchemaReadyDetectsMissingObjects(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop string
	}{
		{"missing table", "DROP TABLE IF EXISTS host_observations"},
		{"missing unique index", "DROP INDEX IF EXISTS idx_findings_project_hash_unique"},
		{"missing plain index", "DROP INDEX IF EXISTS idx_findings_project_severity"},
		{"missing deferrable record index", "DROP INDEX IF EXISTS idx_records_dedup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Repair is a migration, which an open runs only when allowed.
			t.Setenv(config.AutoMigrateEnvVar, "1")
			db, _ := tempSchemaDB(t)
			if _, err := db.ExecContext(t.Context(), tc.drop); err != nil {
				t.Fatalf("%s: %v", tc.drop, err)
			}

			if gaps := db.schemaGaps(t.Context()); len(gaps) == 0 {
				t.Fatalf("schemaGaps accepted a database after %q", tc.drop)
			}

			// And the gap must actually be repaired, not just reported.
			if err := db.EnsureSchemaReady(t.Context()); err != nil {
				t.Fatalf("EnsureSchemaReady: %v", err)
			}
			if gaps := db.schemaGaps(t.Context()); len(gaps) != 0 {
				t.Fatalf("gaps remain after EnsureSchemaReady: %v", gaps)
			}
		})
	}
}

// TestSchemaReadyIgnoresDeferredRecordIndexes covers the handle that postpones
// the http_records read indexes on purpose (the --glob-db scratch merge). It has
// not finished loading yet, so lacking them is not a gap.
func TestSchemaReadyIgnoresDeferredRecordIndexes(t *testing.T) {
	db, _ := tempSchemaDB(t)
	if _, err := db.ExecContext(t.Context(), "DROP INDEX IF EXISTS idx_records_dedup"); err != nil {
		t.Fatalf("drop index: %v", err)
	}

	db.DeferRecordIndexes()
	if gaps := db.schemaGaps(t.Context()); len(gaps) != 0 {
		t.Fatalf("a handle that deferred the record indexes was judged incomplete for lacking them: %v", gaps)
	}
}

// TestSchemaReadyDetectsStaleVersion covers an older database that holds every
// object but still owes the one-time backfills.
func TestSchemaReadyDetectsStaleVersion(t *testing.T) {
	t.Setenv(config.AutoMigrateEnvVar, "1")
	db, _ := tempSchemaDB(t)

	if _, err := db.ExecContext(t.Context(), "UPDATE schema_meta SET version = 0 WHERE id = 1"); err != nil {
		t.Fatalf("roll version back: %v", err)
	}
	if gaps := db.schemaGaps(t.Context()); len(gaps) == 0 {
		t.Fatal("schemaGaps accepted a database at an older schema version")
	}

	if err := db.EnsureSchemaReady(t.Context()); err != nil {
		t.Fatalf("EnsureSchemaReady: %v", err)
	}
	if got := db.schemaVersion(t.Context()); got < currentSchemaVersion {
		t.Fatalf("version still %d after EnsureSchemaReady, want >= %d", got, currentSchemaVersion)
	}
}

// TestSchemaReadyDoesNotWaitOnWriteLock is the performance regression guard.
// Establishing readiness on a current database must not take the write lock, so
// another process holding it cannot delay scan startup.
func TestSchemaReadyDoesNotWaitOnWriteLock(t *testing.T) {
	_, path := tempSchemaDB(t)

	release := holdTx(t, path, false)

	cfg := writableConfig(path)
	cfg.SQLite.BusyTimeout = 4000
	scanner, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("open under write lock: %v", err)
	}
	t.Cleanup(func() { _ = scanner.Close() })

	start := time.Now()
	if err := scanner.EnsureSchemaReady(t.Context()); err != nil {
		t.Fatalf("EnsureSchemaReady under a held write lock: %v", err)
	}
	elapsed := time.Since(start)

	// Released before the handles close: DB.Close runs PRAGMA optimize, which is
	// a write, so leaving the lock held made teardown wait out the whole
	// busy_timeout — 4s of suite time after a 0.4ms assertion.
	release()

	if limit := time.Second; elapsed > limit {
		t.Fatalf("EnsureSchemaReady took %s with the write lock held (limit %s, busy_timeout %dms) — "+
			"schema readiness is taking the write lock again",
			elapsed, limit, cfg.SQLite.BusyTimeout)
	}
}
