package database

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Schema readiness: deciding whether a database already has the shape this
// binary expects, using only reads.
//
// The native scan entry points used to call CreateSchema unconditionally on
// every start. That is 16 CREATE TABLE, 80 ADD COLUMN attempts and 52 CREATE
// INDEX statements, and on an idle local SQLite file it costs 0.7ms — but every
// one of them takes SQLite's single write lock. Against a database another
// vigolium process is writing (a concurrent scan, `serve`, an ingest) the schema
// pass instead queues on the busy_timeout: measured 2.02s at busy_timeout=2000,
// which scales straight to ~15s at the 15000 default, before the scan has sent a
// single request. The read-only check below is 0.38ms under the same held lock.
//
// It has to cover every object CreateSchema creates, not just the ones cheap to
// check. EnsureSchemaCurrent — the older, weaker check on the read commands'
// open path — inspects columnMigrations only, so it accepts a missing table or a
// missing UNIQUE index; that was defensible while every write command still ran
// CreateSchema unconditionally, and stopped being defensible the moment a scan
// started skipping it.

// ddlObjectPattern captures the kind and name of a CREATE statement in the
// schema DDL. Every entry has the shape
// `CREATE [UNIQUE] TABLE|INDEX IF NOT EXISTS <name> ...`.
const ddlObjectPattern = `(?is)^\s*CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX)\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_]+)`

// expectedSchemaObjects is the set of table and index names a current database
// must hold, split by whether a bulk load is allowed to postpone them.
//
// Parsed from the DDL rather than listed by hand: a hand-maintained copy drifts
// on the first schema change, and it drifts in the dangerous direction — a new
// table missing from the copy makes this check pass on a database that does not
// have it. Lazy so the regex is compiled only by a process that opens a
// database, and so an unparsed statement is reported through a real logger
// rather than the no-op one in place during package init.
var expectedSchemaObjects = sync.OnceValue(func() (names struct{ core, deferrable []string }) {
	pattern := regexp.MustCompile(ddlObjectPattern)
	parse := func(ddls []string) []string {
		out := make([]string, 0, len(ddls))
		for _, ddl := range ddls {
			m := pattern.FindStringSubmatch(ddl)
			if m == nil {
				// A statement this parser cannot read must not silently shrink
				// the expected set, which would weaken the check. Returning nil
				// makes readiness always fall through to CreateSchema.
				head, _, _ := strings.Cut(ddl, "\n")
				zap.L().Debug("unparsed schema DDL; schema readiness will always run CreateSchema",
					zap.String("ddl", strings.TrimSpace(head)))
				return nil
			}
			out = append(out, strings.ToLower(m[1]))
		}
		return out
	}
	names.core = parse(slices.Concat(schemaTables, schemaIndexes))
	// The http_records read indexes CreateSchema applies through
	// CreateRecordIndexes. Separate because DeferRecordIndexes legitimately
	// leaves them uncreated for the duration of a bulk load, so a handle that
	// deferred them must not be judged incomplete for lacking them.
	names.deferrable = parse(recordSecondaryIndexes)
	return names
})

// schemaGaps reports, read-only, what this database is missing relative to the
// schema this binary expects: tables, indexes, migrated columns, or the
// migration version. An empty result means the schema is ready as-is.
//
// Every non-empty result means the same thing to the caller — run CreateSchema —
// so "cannot tell" (an unreadable catalog, a fresh file with no tables at all)
// is reported as a gap rather than as an error. A fresh database legitimately
// has no catalog to read, and the answer for it is the same anyway.
func (db *DB) schemaGaps(ctx context.Context) []string {
	gaps, err := db.schemaGapsDetail(ctx)
	switch {
	case errors.Is(err, errSchemaNotInitialized):
		return []string{"schema not initialized"}
	case err != nil:
		return []string{err.Error()}
	}
	return gaps
}

// schemaGapsDetail is schemaGaps with "cannot tell" kept apart from "behind":
// errSchemaNotInitialized for a store with no core table, another error for a
// catalog that could not be read, and otherwise the list of gaps. CheckSchema
// needs the distinction — a reader must not report an unreadable catalog as a
// store that merely needs migrating.
func (db *DB) schemaGapsDetail(ctx context.Context) ([]string, error) {
	expected := expectedSchemaObjects()
	if len(expected.core) == 0 || len(expected.deferrable) == 0 {
		return nil, errors.New("expected-object list unavailable")
	}

	present, err := db.listSchemaObjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("catalog unreadable: %w", err)
	}
	// An absent core table means a fresh or empty file: it needs the full
	// CreateSchema, and being new it has no concurrent writer to contend with.
	if !present[coreTableName] {
		return nil, errSchemaNotInitialized
	}

	var gaps []string
	for _, name := range expected.core {
		if !present[name] {
			gaps = append(gaps, name)
		}
	}
	if !db.deferRecordIndexes {
		for _, name := range expected.deferrable {
			if !present[name] {
				gaps = append(gaps, name)
			}
		}
	}

	// Columns next, and only when every object exists: reading them is the
	// expensive half of this check, and it is wasted on a database that is
	// already going to run CreateSchema for a missing object.
	if len(gaps) == 0 {
		missing, err := db.missingColumnsFrom(ctx, present)
		if err != nil {
			return nil, fmt.Errorf("column catalog unreadable: %w", err)
		}
		gaps = append(gaps, missing...)
	}

	// A legacy integer bool column on Postgres: present, so the column check
	// passes it, but every bool write to it fails until CreateSchema converts
	// it (convertLegacyBoolColumns).
	if len(gaps) == 0 && db.driver == driverPostgres {
		legacy, err := db.legacyBoolColumns(ctx)
		if err != nil {
			return nil, fmt.Errorf("column type catalog unreadable: %w", err)
		}
		for b, typ := range legacy {
			// Only what CreateSchema can convert: an unexpected type it leaves
			// alone would otherwise be a gap no migration ever closes.
			if pgIntegerTypes[typ] {
				gaps = append(gaps, fmt.Sprintf("%s.%s is %s, not boolean", b.Table, b.Column, typ))
			}
		}
		slices.Sort(gaps)
	}

	// The recorded version last. It gates the one-time O(rows) backfills, so a
	// database holding every object but stuck at an older version still has
	// migration work owed.
	if len(gaps) == 0 {
		if v := db.schemaVersion(ctx); v < currentSchemaVersion {
			gaps = append(gaps, fmt.Sprintf("schema version %d < %d", v, currentSchemaVersion))
		}
	}
	return gaps, nil
}

// listSchemaObjects returns the lowercased names of every table and index in
// this database, as one catalog query.
func (db *DB) listSchemaObjects(ctx context.Context) (map[string]bool, error) {
	var query string
	switch db.driver {
	case "sqlite":
		query = `SELECT name FROM sqlite_master WHERE type IN ('table', 'index')`
	case "postgres":
		// 'public' rather than current_schema(): it is the schema every other
		// catalog read in this package pins (ListTables, listColumnsPostgres),
		// and disagreeing with them would make this check and the column check
		// describe different databases — readiness would never pass.
		query = `SELECT tablename AS name FROM pg_catalog.pg_tables WHERE schemaname = 'public'
		         UNION ALL
		         SELECT indexname AS name FROM pg_catalog.pg_indexes WHERE schemaname = 'public'`
	default:
		return nil, fmt.Errorf("unsupported driver: %s", db.driver)
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	present := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		present[strings.ToLower(name)] = true
	}
	return present, rows.Err()
}

// EnsureSchemaReady makes this database usable, running schema DDL only when a
// read-only check shows something is actually missing.
//
// Use it wherever a process opens a store it expects to already be initialized,
// so starting a scan alongside another writer does not queue on the write lock
// just to re-assert a schema that is already correct. A fresh file, a missing
// table, a missing index, a missing migrated column or an older migration
// version all fall through to the full CreateSchema, so this never accepts an
// incomplete schema.
//
// ctx bounds the read-only readiness question only. The repair deliberately runs
// without that deadline: CreateSchema's gated branches are O(rows) — whole-table
// backfills and index builds — so a large database that genuinely owes
// migrations needs however long they take, and cutting it off at a deadline
// derived from a lock-wait budget would turn a slow success into a failure.
func (db *DB) EnsureSchemaReady(ctx context.Context) error {
	// A read-only handle (or read-intent pool) cannot be migrated at all;
	// CreateSchema's own read-only branch reports an unusable schema with a
	// remedy, which is the best answer available here.
	if !db.writable() {
		return db.CreateSchema(ctx)
	}
	// Before the fast path: a store a newer binary stamped has every object this
	// one knows, so "nothing missing" would otherwise let a scan write into a
	// schema it does not understand.
	if err := db.guardWriteDB(ctx); err != nil {
		return err
	}

	gaps, gapErr := db.schemaGapsDetail(ctx)
	if gapErr == nil && len(gaps) == 0 {
		zap.L().Debug("schema ready; skipping schema DDL")
		return nil
	}
	// A fresh file (no core table) is initialized: creating an empty store
	// migrates nobody's data. An initialized store that is behind is
	// migrated only when the configuration allows it.
	if gapErr == nil {
		if refusal := db.refuseImplicitMigration(ctx, gaps); refusal != nil {
			return refusal
		}
	}
	zap.L().Debug("schema incomplete; creating schema", zap.Strings("missing", db.schemaGaps(ctx)))
	return db.CreateSchema(context.WithoutCancel(ctx))
}

// refuseImplicitMigration returns a *SchemaOutdatedError for an initialized
// store that is behind this binary's schema, unless this handle's
// configuration lets an open migrate it (DatabaseConfig.MigratesImplicitly:
// VIGOLIUM_AUTO_MIGRATE, else database.auto_migrate_on_read, default off).
//
// The refusal is the default because a migration is not free: its gated
// backfills are O(rows), it can run past the deadline of the leg that
// happened to open the store, and it leaves the file unreadable by the
// binary that wrote it. `vigolium db migrate` (DB.Migrate) is the explicit
// way, and the error names it with this store's path.
func (db *DB) refuseImplicitMigration(ctx context.Context, gaps []string) error {
	if len(gaps) == 0 || db.cfg.MigratesImplicitly() {
		return nil
	}
	return &SchemaOutdatedError{DBVersion: db.schemaVersion(ctx), Missing: gaps, Path: db.path}
}
