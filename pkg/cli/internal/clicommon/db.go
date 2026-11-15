// Package clicommon holds shared, leaf-level helpers used across the vigolium
// CLI command tree: the database-connection cache, project resolution, the
// --watch loop, logger flushing, and display formatting. It is intentionally
// dependency-light (no imports back into pkg/cli) so command groups can be
// split into their own subpackages and still share this common ground.
package clicommon

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// dbConn is the process-wide cached database connection shared by every command,
// and dbConnIntent the intent it was opened for.
var (
	dbConn       *database.DB
	dbConnIntent OpenIntent
)

// OpenPolicy is how the running command may open the shared database. The CLI
// sets Policy from it in PersistentPreRunE, before anything can open one.
type OpenPolicy struct {
	// Intent is the command's declared intent (the CLI's commandTraits).
	Intent OpenIntent
	// ReadOnly (--read-only) forces IntentEvidence for the whole process: the
	// command must not modify its source.
	ReadOnly bool
	// MustExist is the expanded path of an explicitly pinned SQLite source a
	// pure read command must NOT create ("" = none: the built-in default
	// database is still made on first use). Enforced here rather than at the
	// call sites, so a read path added later inherits the guarantee instead of
	// having to remember it.
	MustExist string
}

// Policy is the running command's open policy. A package var rather than a
// GetDB parameter because GetDB is reached from ~40 call sites that would all
// have to thread a value none of them decides.
var Policy = OpenPolicy{Intent: IntentWrite}

// SourceMissingError reports a pinned database path that is not there.
//
// It is a type rather than a wrapped sentinel so the message can say the useful
// thing once. Unwrapping to fs.ErrNotExist keeps the CLI's error classifier
// mapping it to source_missing by identity rather than by message text, while
// Error() stays free of the stdlib's "file does not exist" tail and of an OS
// strerror string, which is neither locale- nor platform-stable.
type SourceMissingError struct{ Path string }

func (e *SourceMissingError) Error() string {
	return fmt.Sprintf("database %q does not exist. This is a read command, so it will not "+
		"create one — check the path, or run a scan/ingest against it first", e.Path)
}

func (e *SourceMissingError) Unwrap() error { return fs.ErrNotExist }

// SourceIncompatibleError reports a file that opens as SQLite but is not a
// vigolium store.
//
// Refusing it is the other half of the missing-path fix. A pinned path that
// exists is not necessarily the right file, and opening one that is not brings
// vigolium's ~17 tables into existence INSIDE another tool's database — then
// reports `total: 0`, exit 0, which reads as "nothing has been scanned here".
// Two opposite facts, one answer, and the wrong one silently modifies a file
// that belonged to something else.
//
// The distinction is the presence of the core table, not the presence of rows:
// a scanned target with no matching records and a foreign database both look
// empty from the outside.
type SourceIncompatibleError struct{ Path string }

func (e *SourceIncompatibleError) Error() string {
	return fmt.Sprintf("database %q is not a vigolium store: it opens as SQLite but has none of "+
		"vigolium's tables. This is a read command, so it will not create them — check the path, "+
		"or run a scan/ingest against it to initialize it", e.Path)
}

// GetDB returns the cached database connection, opening it on first use with
// the running command's declared intent (Policy.Intent; --read-only forces
// IntentEvidence). configPath is the --config path (may be empty) and dbPath is
// the --db SQLite override (may be empty). When the database is not explicitly
// enabled it defaults to SQLite at the standard location. See GetDBFor.
func GetDB(configPath, dbPath string) (*database.DB, error) {
	return GetDBFor(Policy.Intent, configPath, dbPath)
}

// GetDBFor returns the cached database connection, opening it on first use for
// the given intent. A cached handle is reused whenever it can serve the intent:
// a writer serves reads, and a --read-only evidence handle serves everything
// (the flag forces evidence intent process-wide). A cached read pool asked for
// a write is retired, not closed — something earlier in the command may still
// hold it — and a writer takes its place; both close at exit.
func GetDBFor(intent OpenIntent, configPath, dbPath string) (*database.DB, error) {
	intent = effectiveIntent(intent)
	if dbConn != nil {
		if dbConnIntent.serves(intent) {
			return dbConn, nil
		}
	}

	// Before any open, because opening is what creates the file.
	if err := checkSourceExists(); err != nil {
		return nil, err
	}
	if err := checkSourceIsSQLite(); err != nil {
		return nil, err
	}

	cfg, err := ResolveDatabaseConfig(configPath, dbPath)
	if err != nil {
		return nil, err
	}

	var db *database.DB
	switch intent {
	case IntentRead:
		db, err = openForRead(cfg)
	case IntentEvidence:
		db, err = openForEvidence(cfg)
	default:
		db, err = openForWrite(cfg)
	}
	if err != nil {
		return nil, err
	}

	if dbConn != nil {
		retiredConns = append(retiredConns, dbConn)
	}
	dbConn = db
	dbConnIntent = intent
	openedDBDriver = cfg.Driver
	openedDBPath = config.ExpandPath(cfg.SQLite.Path)
	if cfg.Driver != "sqlite" {
		openedDBPath = cfg.Driver
	}
	return db, nil
}

// ResolveDatabaseConfig applies the CLI's store-selection rules to the loaded
// settings: --db → $VIGOLIUM_DB_PATH (already folded into dbPath by the CLI) →
// config → the built-in default SQLite file.
func ResolveDatabaseConfig(configPath, dbPath string) (*config.DatabaseConfig, error) {
	// LoadSettings, not config.LoadSettings: a broken --config decides which
	// DATABASE this opens, so falling back to defaults here silently pointed the
	// command at ~/.vigolium/database-vgnm.sqlite — creating it if absent — while
	// the operator believed they were working in the store their config names.
	// A discovered-but-unreadable config still degrades to defaults, with a
	// warning; that is the helper's job, not this function's.
	settings, err := LoadSettings(configPath)
	if err != nil {
		return nil, err
	}
	cfg := settings.Database

	// If database is not explicitly enabled, default to SQLite
	if !cfg.Enabled && cfg.Driver == "" {
		cfg.Enabled = true
		cfg.Driver = "sqlite"
		cfg.SQLite.Path = "~/.vigolium/database-vgnm.sqlite"
	}

	// Override SQLite path if --db flag is set
	if dbPath != "" {
		cfg.Driver = "sqlite"
		cfg.SQLite.Path = dbPath
	}
	return &cfg, nil
}

// openForWrite opens the read-write store and makes its schema ready, running
// DDL only when a read-only check finds something missing.
//
// A schema that cannot be made ready is fatal here. Write commands used to call
// CreateSchema themselves and fail on its error; folding that into the opener
// keeps the failure and drops the per-command copy. A store a newer binary
// stamped is refused (schema_too_new) rather than written into.
func openForWrite(cfg *config.DatabaseConfig) (*database.DB, error) {
	db, err := database.NewDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := refuseForeignStore(db); err != nil {
		return nil, err
	}
	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		_ = db.Close()
		var tooNew *database.SchemaTooNewError
		if errors.As(err, &tooNew) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to bring database schema up to date: %w", err)
	}
	return db, nil
}

// openForEvidence is the --read-only open: mode=ro, nothing about the file may
// change, so an outdated schema is reported rather than migrated.
func openForEvidence(cfg *config.DatabaseConfig) (*database.DB, error) {
	// Only meaningful for SQLite; Postgres read-only is a server-side grant.
	if cfg.Driver == "sqlite" {
		cfg.SQLite.ReadOnly = true
	}
	db, err := database.NewDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := refuseForeignStore(db); err != nil {
		return nil, err
	}
	// EnsureSchemaCurrent on a read-only handle is a check: an outdated or
	// too-new schema is fatal — it cannot be migrated, and every query that
	// follows would fail on a missing column with an error that names no
	// remedy. Any other failure is best-effort, so it only warns.
	if schemaErr := db.EnsureSchemaCurrent(context.Background()); schemaErr != nil {
		if errors.Is(schemaErr, database.ErrSchemaOutdated) || errors.Is(schemaErr, database.ErrSchemaTooNew) {
			// Close before returning: the handle never reaches dbConn on this
			// path, so nothing downstream can close it.
			_ = db.Close()
			return nil, schemaErr
		}
		zap.L().Warn("Failed to check database schema", zap.Error(schemaErr))
	}
	return db, nil
}

// openForRead opens the read pool: query_only, deferred transactions, no
// journal-mode PRAGMA, no checkpointing (see database.openSQLiteReader). A read
// command therefore never takes the write lock and never waits on a scan
// writing the same store.
//
// Its schema is checked with catalog reads only. A store that is behind is
// migrated through a SEPARATE, short-lived writer when
// database.auto_migrate_on_read is on (the default for one release, D23), and
// refused with schema_outdated and the `vigolium db migrate` remedy when it is
// off. A missing or table-less default store is initialized the same way: that
// is creating an empty store, not migrating anyone's data. A pinned source that
// is missing or foreign never gets here (checkSourceExists / refuseForeignStore).
func openForRead(cfg *config.DatabaseConfig) (*database.DB, error) {
	if cfg.Driver == "sqlite" {
		path := database.ExpandPath(cfg.SQLite.Path)
		if path == ":memory:" || strings.Contains(path, ":memory:") {
			// Every connection to :memory: is its own database; a read pool on it
			// would see nothing the writer made.
			return openForWrite(cfg)
		}
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			if err := migrateThroughWriter(cfg); err != nil {
				return nil, err
			}
		}
	}

	open := func() (*database.DB, error) {
		rcfg := *cfg
		rcfg.ReadIntent = true
		db, err := database.NewDB(&rcfg)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		return db, nil
	}

	db, err := open()
	if err != nil {
		return nil, err
	}
	if err := refuseForeignStore(db); err != nil {
		return nil, err
	}

	schemaErr := db.CheckSchema(context.Background())
	migrate := errors.Is(schemaErr, database.ErrSchemaNotInitialized) ||
		(errors.Is(schemaErr, database.ErrSchemaOutdated) && cfg.AutoMigrateOnRead)
	if !migrate {
		if schemaErr != nil {
			_ = db.Close()
			return nil, schemaErr
		}
		return db, nil
	}

	// Close the reader first so the migration's DDL is not racing a pool this
	// process holds; reopen once the schema is current.
	_ = db.Close()
	zap.L().Debug("database schema is behind; migrating before the read", zap.NamedError("schema", schemaErr))
	if err := migrateThroughWriter(cfg); err != nil {
		return nil, err
	}
	if db, err = open(); err != nil {
		return nil, err
	}
	if err := db.CheckSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// migrateThroughWriter opens a short-lived read-write handle, makes the schema
// ready, and closes it. It is how a read-intent open initializes or upgrades a
// store without its own pool ever holding the write lock.
func migrateThroughWriter(cfg *config.DatabaseConfig) error {
	wcfg := *cfg
	wcfg.ReadIntent = false
	w, err := openForWrite(&wcfg)
	if err != nil {
		return err
	}
	return w.Close()
}

// refuseForeignStore closes db and returns SourceIncompatibleError when a pure
// read against a pinned source finds a file that is not a vigolium store.
//
// A pure read against a pinned source must not bring vigolium's tables into
// being inside a file that never had them. Checked before any migration, which
// is exactly what would create them.
func refuseForeignStore(db *database.DB) error {
	if Policy.MustExist != "" && !db.HasVigoliumSchema(context.Background()) {
		_ = db.Close()
		return &SourceIncompatibleError{Path: Policy.MustExist}
	}
	return nil
}

// checkSourceExists refuses to open a pinned source that is absent, or that is a
// directory standing where a database file should be. A nil return means the
// path is there — not that it is a vigolium store, which the schema check and
// the source_incompatible code downstream still decide.
func checkSourceExists() error {
	if Policy.MustExist == "" {
		return nil
	}
	info, err := os.Stat(Policy.MustExist)
	if err != nil {
		if os.IsNotExist(err) {
			return &SourceMissingError{Path: Policy.MustExist}
		}
		return fmt.Errorf("cannot read database %q: %w", Policy.MustExist, err)
	}
	if info.IsDir() {
		return fmt.Errorf("database %q is a directory, not a file", Policy.MustExist)
	}
	return nil
}

// checkSourceIsSQLite refuses a pinned source that exists but is not a SQLite
// file — a JSONL export, most often — which would otherwise fail deep in the
// driver as "file is not a database (26)". An empty file passes: SQLite
// treats it as a new database, and the schema check decides from there.
func checkSourceIsSQLite() error {
	if Policy.MustExist == "" {
		return nil
	}
	info, err := os.Stat(Policy.MustExist)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return nil
	}
	if isSQLite, err := database.IsSQLiteFile(Policy.MustExist); err == nil && !isSQLite {
		return CLIError{
			//vigolium:not-usage the file's contents, not the command line
			Err:  fmt.Errorf("--db %q is not a SQLite database", Policy.MustExist),
			Code: apicontract.CodeSourceUnreadable,
			Hint: "To read a JSONL export (or any standalone file) pass -S: -S --db " + Policy.MustExist,
		}
	}
	return nil
}

// openedDBPath records which database the cached connection actually opened.
//
// The open order is --db → $VIGOLIUM_DB_PATH → config → the built-in default,
// and that last rung is ONE SHARED FILE under a single default project — so a
// command that falls through to it is reading every target that ever landed
// there. That is a cross-engagement mixing hazard a consumer cannot detect from
// the outside, which is why the resolved path is reported in every -j envelope
// (and in scan.started): a driver can then assert the store it read rather than
// trusting that its pin survived a subprocess chain.
var openedDBPath string

// openedDBDriver records which driver backed that open, because OpenedDBPath
// alone cannot be told apart: for PostgreSQL it returns the literal "postgres",
// which is also a perfectly legal relative filename. Anything deciding whether
// the opened store can be named on a command line — a `--db` in a follow-up
// query — has to ask the driver, not pattern-match the path.
var openedDBDriver string

// OpenedDBPath returns the resolved path of the database currently open, or ""
// before any open. For a non-SQLite driver it returns the driver name, since
// there is no single file to name.
func OpenedDBPath() string { return openedDBPath }

// OpenedDBDriver returns the driver that backed the current open ("sqlite",
// "postgres", …), or "" before any open.
func OpenedDBDriver() string { return openedDBDriver }

// SetOpenedDBPath overrides the recorded path. For tests that exercise what is
// reported about a read without opening a database to produce it.
func SetOpenedDBPath(path string) { openedDBPath = path }

// SetOpenedDBDriver overrides the recorded driver, for the same reason.
func SetOpenedDBDriver(driver string) { openedDBDriver = driver }

// CloseDatabaseOnExit closes the cached connection if open. Safe to defer.
func CloseDatabaseOnExit() {
	closeRetired()
	if dbConn != nil {
		_ = dbConn.Close()
	}
}

// ResetDBCache closes and clears the cached connection. Used by `db clean`
// before deleting the underlying SQLite file.
func ResetDBCache() {
	closeRetired()
	if dbConn != nil {
		_ = dbConn.Close()
		dbConn = nil
	}
}

// SetDBCache replaces the cached connection. Used by `db clean` after it
// recreates the database with a fresh schema.
func SetDBCache(db *database.DB) {
	dbConn = db
	dbConnIntent = IntentWrite
}

// retiredConns are read pools a later write-intent open superseded. Kept open
// until exit because a repository built on one may still be in use.
var retiredConns []*database.DB

func closeRetired() {
	for _, c := range retiredConns {
		_ = c.Close()
	}
	retiredConns = nil
}
