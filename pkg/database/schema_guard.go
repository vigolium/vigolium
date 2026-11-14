package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/apicontract"
)

// Schema compatibility guard.
//
// schema_meta (one row, id = 1) records three things about a store:
//
//   - version: the schema revision of the newest binary that migrated it;
//   - min_reader_version: the oldest binary revision that can still READ it;
//   - written_by / updated_at: which vigolium build last stamped it, and when.
//
// A binary whose currentSchemaVersion is C may read a store whose
// min_reader_version <= C, and may write or migrate it only when version <= C.
// Additive migrations (new columns, new tables) leave min_reader_version where
// it is, so an older binary keeps reading a store a newer one upgraded; a
// breaking migration raises it, and older binaries then refuse with
// schema_too_new instead of failing mid-query.
//
// Binaries from before this guard still open newer stores and, before the MAX
// fix in setSchemaVersion, stamped their own lower version over them. Nothing
// here can stop an old binary; the guard protects the stores from now on.

// minReaderVersion is the min_reader_version this binary stamps. Schema v6
// re-keyed finding hashes (identity v2): a pre-v6 binary would compute the old
// hash for every re-detection and fork the finding, so it is refused.
const minReaderVersion = 6

// MinReaderVersion exposes the reader floor this binary writes, for
// `vigolium version --json`.
func MinReaderVersion() int { return minReaderVersion }

// binaryVersion is what written_by records. Set by the CLI at startup (the
// package cannot import it); "dev" until then.
var binaryVersion atomic.Value

// SetBinaryVersion records the running vigolium version for schema_meta.written_by.
func SetBinaryVersion(v string) {
	if strings.TrimSpace(v) != "" {
		binaryVersion.Store(v)
	}
}

func currentBinaryVersion() string {
	if v, ok := binaryVersion.Load().(string); ok {
		return v
	}
	return "dev"
}

// SchemaInfo is what schema_meta says about a store.
type SchemaInfo struct {
	Version          int    `json:"version"`
	MinReaderVersion int    `json:"min_reader_version"`
	WrittenBy        string `json:"written_by,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// SchemaInfo reads schema_meta. A store with no schema_meta row (fresh, or
// created before versioning) reports the zero value and no error; a store from
// before the v2 columns reports its version with min_reader_version 1, which is
// what every such store honestly requires.
func (db *DB) SchemaInfo(ctx context.Context) (SchemaInfo, error) {
	var (
		info      SchemaInfo
		writtenBy sql.NullString
		updatedAt sql.NullString
	)
	err := db.QueryRowContext(ctx,
		"SELECT version, min_reader_version, written_by, updated_at FROM schema_meta WHERE id = 1").
		Scan(&info.Version, &info.MinReaderVersion, &writtenBy, &updatedAt)
	if err == nil {
		info.WrittenBy, info.UpdatedAt = writtenBy.String, updatedAt.String
		return info, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return SchemaInfo{}, nil
	}
	// A v1 schema_meta has only the version column.
	if verr := db.QueryRowContext(ctx, "SELECT version FROM schema_meta WHERE id = 1").Scan(&info.Version); verr != nil {
		if errors.Is(verr, sql.ErrNoRows) || !db.tableExists(ctx, "schema_meta") {
			return SchemaInfo{}, nil
		}
		return SchemaInfo{}, verr
	}
	info.MinReaderVersion = min(info.Version, 1)
	return info, nil
}

// ErrSchemaTooNew is the sentinel every *SchemaTooNewError unwraps to.
var ErrSchemaTooNew = errors.New("database schema is newer than this vigolium")

// SchemaTooNewError reports a store this binary must not touch: either it
// cannot read it at all (min_reader_version above this binary), or it can read
// but must not write a schema it does not know (Write).
type SchemaTooNewError struct {
	DBVersion        int
	MinReaderVersion int
	Binary           int
	WrittenBy        string
	Write            bool
}

func (e *SchemaTooNewError) Error() string {
	by := ""
	if e.WrittenBy != "" {
		by = " (written by vigolium " + e.WrittenBy + ")"
	}
	if e.Write {
		return fmt.Sprintf("database schema v%d%s is newer than this vigolium's v%d; refusing to write it — upgrade vigolium, or use a read command",
			e.DBVersion, by, e.Binary)
	}
	return fmt.Sprintf("database schema v%d%s needs a reader of at least v%d and this vigolium reads up to v%d — upgrade vigolium",
		e.DBVersion, by, e.MinReaderVersion, e.Binary)
}

func (e *SchemaTooNewError) Is(target error) bool        { return target == ErrSchemaTooNew }
func (e *SchemaTooNewError) Code() apicontract.ErrorCode { return apicontract.CodeSchemaTooNew }

// SchemaOutdatedError reports a store written by an older vigolium that a
// read-intent open will not migrate. It unwraps to ErrSchemaOutdated.
type SchemaOutdatedError struct {
	DBVersion int
	Missing   []string
}

// schemaOutdatedListLimit bounds how many gaps the message names; the rest are
// counted. A v0 store can be missing dozens of objects.
const schemaOutdatedListLimit = 6

func (e *SchemaOutdatedError) Error() string {
	missing := e.Missing
	more := ""
	if len(missing) > schemaOutdatedListLimit {
		more = fmt.Sprintf(", and %d more", len(missing)-schemaOutdatedListLimit)
		missing = missing[:schemaOutdatedListLimit]
	}
	return fmt.Sprintf("%v (schema v%d, this vigolium expects v%d; missing: %s%s)\n"+
		"  run `vigolium db migrate` to upgrade it, or set database.auto_migrate_on_read: true",
		ErrSchemaOutdated, e.DBVersion, currentSchemaVersion, strings.Join(missing, ", "), more)
}

func (e *SchemaOutdatedError) Is(target error) bool        { return target == ErrSchemaOutdated }
func (e *SchemaOutdatedError) Code() apicontract.ErrorCode { return apicontract.CodeSchemaOutdated }

// ErrSchemaNotInitialized marks a store with no vigolium tables at all: a fresh
// file rather than a stale one. CheckSchema returns it so the opener can decide
// between initializing (its own default store) and refusing (a pinned path).
var ErrSchemaNotInitialized = errSchemaNotInitialized

// guardRead refuses a store whose min_reader_version is above this binary.
func guardRead(info SchemaInfo) error {
	if info.Version > currentSchemaVersion && info.MinReaderVersion > currentSchemaVersion {
		return &SchemaTooNewError{
			DBVersion: info.Version, MinReaderVersion: info.MinReaderVersion,
			Binary: currentSchemaVersion, WrittenBy: info.WrittenBy,
		}
	}
	return nil
}

// guardWrite refuses to write or migrate a store a newer binary has stamped.
func guardWrite(info SchemaInfo) error {
	if info.Version > currentSchemaVersion {
		return &SchemaTooNewError{
			DBVersion: info.Version, MinReaderVersion: info.MinReaderVersion,
			Binary: currentSchemaVersion, WrittenBy: info.WrittenBy, Write: true,
		}
	}
	return nil
}

// guardWriteDB is guardWrite against this handle's schema_meta. An unreadable
// schema_meta is not a refusal: a fresh store has none, and the migration that
// follows creates it.
func (db *DB) guardWriteDB(ctx context.Context) error {
	info, err := db.SchemaInfo(ctx)
	if err != nil {
		return nil
	}
	return guardWrite(info)
}

// CheckSchema answers, with catalog reads only, whether this store can be read
// as-is by this binary. It never takes a write lock and never migrates.
//
//   - nil: current (or newer but readable — additive migrations only add);
//   - *SchemaTooNewError: min_reader_version is above this binary;
//   - ErrSchemaNotInitialized: no vigolium tables at all;
//   - *SchemaOutdatedError: tables, indexes, columns or the version are behind.
//
// The read commands' opener decides what to do with the last two: migrate
// through a separate writer (database.auto_migrate_on_read) or refuse with the
// `vigolium db migrate` remedy.
func (db *DB) CheckSchema(ctx context.Context) error {
	info, err := db.SchemaInfo(ctx)
	if err != nil {
		return fmt.Errorf("read schema_meta: %w", err)
	}
	if err := guardRead(info); err != nil {
		return err
	}
	if info.Version > currentSchemaVersion {
		return nil
	}
	gaps, err := db.schemaGapsDetail(ctx)
	switch {
	case errors.Is(err, errSchemaNotInitialized):
		return ErrSchemaNotInitialized
	case err != nil:
		return err
	case len(gaps) > 0:
		return &SchemaOutdatedError{DBVersion: info.Version, Missing: gaps}
	}
	return nil
}

// MigrateResult describes one explicit migration (`vigolium db migrate`).
type MigrateResult struct {
	FromVersion      int      `json:"from_version"`
	ToVersion        int      `json:"to_version"`
	MinReaderVersion int      `json:"min_reader_version"`
	WrittenBy        string   `json:"written_by,omitempty"`
	Applied          []string `json:"applied"`
	AlreadyCurrent   bool     `json:"already_current"`
}

// Migrate brings this store up to the binary's schema and reports what it
// changed. It is the explicit form of the migration every writer runs on open,
// and the remedy SchemaOutdatedError names.
//
// The migration itself runs without ctx's deadline, for the reason
// EnsureSchemaReady gives: its gated work is O(rows), and a large store that
// owes it needs however long it takes.
func (db *DB) Migrate(ctx context.Context) (*MigrateResult, error) {
	if !db.writable() {
		return nil, errors.New("migrate needs a writable database (drop --read-only)")
	}
	before, err := db.SchemaInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("read schema_meta: %w", err)
	}
	if err := guardWrite(before); err != nil {
		return nil, err
	}
	res := &MigrateResult{FromVersion: before.Version, Applied: []string{}}

	gaps, gapErr := db.schemaGapsDetail(ctx)
	switch {
	case errors.Is(gapErr, errSchemaNotInitialized):
		res.Applied = append(res.Applied, "initialize schema")
	case gapErr != nil:
		return nil, gapErr
	default:
		res.Applied = append(res.Applied, gaps...)
	}

	if len(res.Applied) > 0 {
		if err := db.CreateSchema(context.WithoutCancel(ctx)); err != nil {
			return nil, err
		}
		if remaining, err := db.schemaGapsDetail(ctx); err != nil || len(remaining) > 0 {
			if err == nil {
				err = fmt.Errorf("still missing: %s", strings.Join(remaining, ", "))
			}
			return nil, fmt.Errorf("migration incomplete: %w", err)
		}
	} else {
		res.AlreadyCurrent = true
	}

	after, err := db.SchemaInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("read schema_meta after migration: %w", err)
	}
	res.ToVersion = after.Version
	res.MinReaderVersion = after.MinReaderVersion
	res.WrittenBy = after.WrittenBy
	return res, nil
}
