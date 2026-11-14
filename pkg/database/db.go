package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/utils"
	"go.uber.org/zap"
)

// envSQLTrace opts into per-statement SQL logging on top of --debug. Named here
// rather than inlined so it is greppable — it is the only way to reach the hook.
const envSQLTrace = "VIGOLIUM_SQL_TRACE"

// driverPostgres / driverSQLite are the values DB.driver takes. Named so the
// driver-conditional branches (timestamp precision, DDL adaptation, upserts)
// are greppable rather than scattered string literals.
const (
	driverPostgres = "postgres"
	driverSQLite   = "sqlite"
)

// DB wraps bun.DB with additional metadata
type DB struct {
	*bun.DB
	driver string

	// Full-text search capability, discovered on first use rather than assumed
	// from how this handle was opened. See HasFTS.
	ftsMu    sync.Mutex
	ftsKnown bool
	hasFTS   bool // true if FTS5 (SQLite) or tsvector (Postgres) is available

	// ckptStop stops the background WAL checkpointer (file-backed SQLite only;
	// nil otherwise). Closed once by Close().
	ckptStop     chan struct{}
	ckptStopOnce sync.Once

	// readOnly is set when the handle was opened with SQLiteConfig.ReadOnly. It
	// makes CreateSchema a no-op: a read-only source cannot be migrated, and the
	// read commands call CreateSchema unconditionally on open.
	readOnly bool

	// reader is set when the handle was opened with DatabaseConfig.ReadIntent: a query_only pool for read commands. Like
	// readOnly it never migrates, optimizes or checkpoints; unlike readOnly it is
	// the ordinary read path for a live working store, not evidence mode. See
	// openSQLiteReader.
	reader bool

	// cfg is the configuration this handle was opened from, kept so OpenReader
	// can open a second, read-intent pool on the same store.
	cfg config.DatabaseConfig

	// ownedSidecars names the database whose -wal/-shm files this read-only open
	// brought into existence; Close removes them again. Empty when there is
	// nothing to reclaim. See reclaimSidecars.
	ownedSidecars string

	// path is the resolved SQLite file this handle opened, empty for Postgres and
	// ":memory:" for an in-memory store. Reported by Path().
	path string

	// deferRecordIndexes postpones the http_records read indexes past CreateSchema
	// so a bulk load does not maintain them per row. See DeferRecordIndexes.
	deferRecordIndexes bool
}

// SQLite WAL tuning. wal_autocheckpoint runs an automatic PASSIVE checkpoint
// after this many WAL pages accumulate; mmap_size enables memory-mapped reads.
// These are applied per-connection via the DSN. The autocheckpoint alone can't
// reclaim the WAL while a reader pins old frames (the scan-on-receive poller,
// status-tick counts, and read API calls all hold read locks in a long-running
// server), so startWALCheckpointer also forces a TRUNCATE checkpoint on a timer.
const (
	sqliteWALAutocheckpoint = 1000      // pages (~4 MiB at 4 KiB/page)
	sqliteMmapSize          = 268435456 // 256 MiB
	walCheckpointInterval   = 5 * time.Minute
)

// NewDB creates database connection based on config
func NewDB(cfg *config.DatabaseConfig) (*DB, error) {
	if cfg == nil {
		return nil, fmt.Errorf("database config is nil")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid database config: %w", err)
	}

	var sqldb *sql.DB
	var bunDB *bun.DB
	var driver string

	// Sampled BEFORE the open, so "this open made them" is a fact rather than a
	// guess. Only a read-only open can own sidecars: every other path checkpoints
	// and removes them itself on close.
	var ownedSidecarPath string
	if cfg.Driver == "sqlite" && cfg.SQLite.ReadOnly {
		if path := expandPath(cfg.SQLite.Path); !sidecarsPresent(path) {
			ownedSidecarPath = path
		}
	}

	switch cfg.Driver {
	case "sqlite":
		var err error
		sqldb, err = openSQLite(&cfg.SQLite, cfg.ReadIntent)
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite: %w", err)
		}
		bunDB = bun.NewDB(sqldb, NewSQLiteDialect())
		driver = "sqlite"

	case "postgres":
		var err error
		sqldb, err = openPostgres(&cfg.Postgres, cfg.ReadIntent)
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL: %w", err)
		}
		bunDB = bun.NewDB(sqldb, NewPGDialect())
		driver = "postgres"

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	db := &DB{
		DB:            bunDB,
		driver:        driver,
		readOnly:      driver == "sqlite" && cfg.SQLite.ReadOnly,
		reader:        cfg.ReadIntent && (driver != "sqlite" || !cfg.SQLite.ReadOnly),
		ownedSidecars: ownedSidecarPath,
		cfg:           *cfg,
	}
	if driver == "sqlite" {
		db.path = expandPath(cfg.SQLite.Path)
	}

	// Per-statement SQL logging is opt-in on top of debug level, not implied by it.
	// A scan issues thousands of writes, so this hook is the bulk of --debug output
	// and formatting/emitting every statement is itself an observer effect on the
	// write path — which made --debug unusable for diagnosing anything else.
	// Set VIGOLIUM_SQL_TRACE=1 with --debug when you actually want query tracing.
	if zap.L().Core().Enabled(zap.DebugLevel) && utils.EnvTruthy(envSQLTrace) {
		db.DB = db.WithQueryHook(debugQueryHook{})
	}

	// Periodically truncate the WAL for file-backed SQLite so it can't grow
	// without bound over a long-running process. No-op for Postgres and
	// in-memory SQLite (no WAL file). Stopped by Close().
	// Never on a read-only handle: the checkpointer's whole job is to rewrite the
	// WAL, which is exactly the mutation read-only mode exists to prevent.
	// Nor on a read-intent handle: rewriting the WAL is the writer's job, and a
	// reader that checkpoints competes with the very writer it is reading past.
	if driver == "sqlite" && !strings.Contains(cfg.SQLite.Path, ":memory:") && !cfg.SQLite.ReadOnly && !cfg.ReadIntent {
		db.startWALCheckpointer()
	}

	return db, nil
}

// startWALCheckpointer launches a background goroutine that forces a TRUNCATE
// WAL checkpoint every walCheckpointInterval, reclaiming WAL disk space that the
// automatic PASSIVE checkpoint can't while readers pin old frames. The ticker
// fires only in long-running processes (a short CLI scan exits before the first
// tick); the goroutine is stopped by Close().
func (db *DB) startWALCheckpointer() {
	db.ckptStop = make(chan struct{})
	stop := db.ckptStop
	go func() {
		ticker := time.NewTicker(walCheckpointInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				// TRUNCATE is right HERE and wrong on the open path: this
				// goroutine only exists in a long-running process, where
				// reclaiming the file length is the whole point and waiting for a
				// reader delays nothing a user is watching.
				_, _ = checkpointWAL(ctx, db, "TRUNCATE")
				// Refresh planner stats on the same cadence so a long-running
				// server keeps good plans as the tables grow.
				db.Optimize(ctx)
				cancel()
			}
		}
	}()
}

// rowQuerier is the one method both *sql.DB — the raw handle openSQLite holds
// before bun wraps it — and *DB provide.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// checkpointWAL runs a checkpoint, READS ITS RESULT ROW, and logs the outcome.
// It reports whether the checkpoint gave up waiting for readers.
//
// Reading the row is the whole reason it exists. `PRAGMA wal_checkpoint` reports
// a checkpoint it could not complete as busy=1 in its result row and returns no
// error, so the conventional `if _, err := Exec(...); err != nil` form is blind
// to it: a TRUNCATE that blocked for the full busy_timeout and then gave up
// logged absolutely nothing. Measured against one pinned WAL reader: 15.147s,
// busy=1, err=nil. A busy result is therefore logged as loudly as a failure —
// it means WAL space was not reclaimed and the call sat on the busy_timeout to
// find that out.
func checkpointWAL(ctx context.Context, q rowQuerier, mode string) (busy bool, err error) {
	start := time.Now()
	// Scanned into NullInt64 because a driver that returns no row rather than
	// the documented 3-column result must degrade to "unknown", not to an error
	// on a checkpoint that may well have succeeded.
	var busyCol, walPages, checkpointed sql.NullInt64
	err = q.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busyCol, &walPages, &checkpointed)
	busy = busyCol.Int64 != 0

	fields := []zap.Field{
		zap.String("mode", mode),
		zap.Duration("elapsed", time.Since(start)),
		zap.Int64("wal_pages", walPages.Int64),
		zap.Int64("checkpointed", checkpointed.Int64),
		zap.Bool("busy", busy),
	}
	switch {
	case err != nil:
		zap.L().Debug("WAL checkpoint failed", append(fields, zap.Error(err))...)
	case busy:
		zap.L().Debug("WAL checkpoint blocked by a reader; WAL not reclaimed", fields...)
	default:
		zap.L().Debug("WAL checkpoint complete", fields...)
	}
	return busy, err
}

// NewDBFromBun wraps an existing bun.DB for use in tests or external tooling.
func NewDBFromBun(bunDB *bun.DB, driver string) *DB {
	return &DB{DB: bunDB, driver: driver}
}

// sqliteFileURIPath renders a filesystem path as the path component of a SQLite
// `file:` URI: absolute, slash-separated, and percent-encoded.
//
// Encoding is what makes the URI address the file it names. The driver parses
// everything after the first '?' as query parameters and everything after '#' as
// a fragment, so an unencoded path containing either silently became a DIFFERENT
// database — `/tmp/a#b/run.sqlite` attached `/tmp/a`, and `/tmp/a?b/run.sqlite`
// lost every parameter after it, including mode=ro. A literal '%' is encoded for
// the same reason in reverse: `%41` in a real directory name would otherwise be
// decoded back to 'A'.
//
// Made absolute first: a URI filename resolves against the process working
// directory, not against anything the caller may assume.
//
// A '?' is rejected rather than encoded. Measured against the modernc driver in
// go.mod: it parses the encoded form's %3F back out before SQLite sees it, so
// the parameters are still lost, and there is no spelling of such a path that
// works. An error is strictly better than the silent empty database that was
// there before. (See attachSpec, which hit the same wall from the ATTACH side.)
func sqliteFileURIPath(path string) (string, error) {
	if strings.Contains(path, "?") {
		return "", fmt.Errorf("cannot open %q: the SQLite driver cannot address a path containing '?'", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve database path %q: %w", path, err)
	}
	if runtime.GOOS == "windows" {
		// A Windows URI path is "/C:/dir/file", with forward slashes.
		abs = "/" + filepath.ToSlash(abs)
	}
	return (&url.URL{Path: abs}).EscapedPath(), nil
}

// sqliteDSNFilename renders path for the read-WRITE DSN, which the driver reads
// as a bare filename unless it begins with "file:".
//
// Only a path carrying '?', '#' or '%' is promoted to a URI; everything else is
// returned untouched. That asymmetry is deliberate: a bare filename needs no
// encoding and is what every existing deployment's DSN already looks like, so
// promoting all of them would change behaviour for millions of paths to fix the
// handful that were broken. ":memory:" is likewise passed through — it is not a
// path and a URI form of it means something else entirely.
func sqliteDSNFilename(path string) (string, error) {
	if path == ":memory:" || !strings.ContainsAny(path, "?#%") {
		return path, nil
	}
	uri, err := sqliteFileURIPath(path)
	if err != nil {
		return "", err
	}
	return "file:" + uri, nil
}

// openSQLiteReadOnly opens an existing SQLite file without modifying it.
//
// Three things are deliberately omitted relative to the read-write path, because
// each one is a write to the artifact:
//
//   - no os.MkdirAll — a missing file is an error, not a new database;
//   - no journal_mode PRAGMA — setting it rewrites the header, which is what
//     flipped evidence files from `delete` to `wal` and changed their hash;
//   - no startup wal_checkpoint of any mode — even PASSIVE, which the read-write
//     path does run, rewrites both the main file and the -wal sidecar.
//
// `mode=ro` is the driver's own read-only mode; it still reads a pre-existing
// -wal sidecar, so a database another process left mid-WAL is read correctly
// rather than as a stale snapshot. `immutable=1` would be faster and is
// deliberately NOT used: it tells SQLite to assume the file cannot change, which
// silently returns wrong data if it does.
//
// What mode=ro does NOT avoid is the shared-memory index: reading a WAL-mode
// database requires a -shm, and SQLite creates one (and an empty -wal) when it
// is absent. So a --read-only pass over an evidence file left two new files
// beside it while an ordinary read left none — the read-write path creates the
// same sidecars but checkpoints and removes them on close. The returned
// `created` list is what Close reclaims to make the two paths symmetric; the
// main file was, and remains, byte-identical either way.
func openSQLiteReadOnly(path string, cfg *config.SQLiteConfig) (*sql.DB, error) {
	if path == ":memory:" {
		return nil, errors.New("read-only mode requires a file-backed database, not :memory: storage")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database file not readable: %w", err)
	}

	uri, err := sqliteFileURIPath(path)
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf(
		"file:%s?mode=ro&_pragma=busy_timeout(%d)&_pragma=query_only(1)&_pragma=cache_size(%d)&_pragma=temp_store(memory)&_pragma=mmap_size(%d)",
		uri, cfg.BusyTimeout, cfg.CacheSize, sqliteMmapSize,
	)
	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, err
	}
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to open database read-only: %w", err)
	}
	maxConns := cfg.MaxOpenConns
	if maxConns <= 0 {
		maxConns = 8
	}
	sqldb.SetMaxOpenConns(maxConns)
	sqldb.SetMaxIdleConns(maxConns)
	return sqldb, nil
}

// readerMaxOpenConns caps a read-intent pool. Reads in WAL mode run in
// parallel with the writer, but a CLI read issues a handful of queries at most,
// and a server's list/get traffic should not be able to hold more of the file's
// shared-memory slots than this.
const readerMaxOpenConns = 4

// openSQLiteReader opens the read-intent pool on a live store: the ordinary
// path for read commands and the server's list/get handlers.
//
// It differs from the read-write open in exactly the ways that made a read
// contend with a writer:
//
//   - query_only(1): a write through this pool is a driver error, not a lock
//     acquisition that queues behind a scan for busy_timeout;
//   - _txlock=deferred: an explicit BEGIN takes no lock until it reads, where
//     the writer's immediate would take the write lock up front;
//   - no journal_mode PRAGMA: setting it rewrites the header, and a reader has
//     no business deciding the store's journal mode;
//   - no startup checkpoint and no checkpointer goroutine (see NewDB).
//
// It is NOT mode=ro, which stays reserved for --read-only evidence mode:
// mode=ro cannot create a missing -shm on a live WAL database, so it fails
// exactly when a scan is writing — the case this pool exists for.
//
// The file must already exist: a reader that created it would be the "read
// silently becomes a new empty database" bug the source-must-exist guard
// fixed. The CLI initializes a missing default store through a writer first.
func openSQLiteReader(path string, cfg *config.SQLiteConfig) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("database file not readable: %w", err)
	}
	dsnPath, err := sqliteDSNFilename(path)
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf(
		"%s?_pragma=busy_timeout(%d)&_pragma=query_only(1)&_pragma=cache_size(%d)&_pragma=temp_store(memory)&_pragma=mmap_size(%d)&_txlock=deferred",
		dsnPath, cfg.BusyTimeout, cfg.CacheSize, sqliteMmapSize,
	)
	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, err
	}
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to open database for reading: %w", err)
	}
	maxConns := readerMaxOpenConns
	if cfg.MaxOpenConns > 0 && cfg.MaxOpenConns < maxConns {
		maxConns = cfg.MaxOpenConns
	}
	sqldb.SetMaxOpenConns(maxConns)
	sqldb.SetMaxIdleConns(maxConns)
	return sqldb, nil
}

// writable reports whether this handle may write: false for --read-only
// evidence handles and read-intent pools alike.
func (db *DB) writable() bool { return !db.readOnly && !db.reader }

// IsReader reports whether this handle is a read-intent pool.
func (db *DB) IsReader() bool { return db.reader }

// OpenReader opens a second, read-intent pool on the store this handle opened,
// for a long-running process that wants its list/get traffic off the writer's
// pool. The caller owns closing it.
//
// It returns (db, false) — the handle itself, nothing new to close — where a
// separate pool would add nothing: in-memory SQLite (each connection is its own
// database), a handle that is already read-only or a reader, or a handle that
// was not opened by NewDB.
func (db *DB) OpenReader() (*DB, bool, error) {
	if !db.writable() || db.cfg.Driver == "" {
		return db, false, nil
	}
	if db.driver == driverSQLite && (db.path == "" || db.path == ":memory:" || strings.Contains(db.path, ":memory:")) {
		return db, false, nil
	}
	cfg := db.cfg
	cfg.ReadIntent = true
	r, err := NewDB(&cfg)
	if err != nil {
		return nil, false, err
	}
	return r, true, nil
}

// sidecarSuffixes are the files SQLite keeps beside a WAL-mode database.
var sidecarSuffixes = []string{"-wal", "-shm"}

// sidecarsPresent reports whether any sidecar already exists for path.
func sidecarsPresent(path string) bool {
	for _, suffix := range sidecarSuffixes {
		if _, err := os.Stat(path + suffix); err == nil {
			return true
		}
	}
	return false
}

// reclaimSidecars removes the -wal/-shm files this handle's open created,
// leaving the directory as it was found. Called from Close, after the sql.DB is
// closed so our own descriptors are gone.
//
// A non-empty -wal is left alone. This handle never wrote a frame — it was
// opened query_only — so frames there came from another process writing
// concurrently, and deleting that WAL would discard its committed transactions.
// Refusing is the whole safety argument: the only file this removes is one that
// is both ours and empty.
//
// Best-effort throughout. A removal that fails leaves a file that the next open
// will simply reuse, which is the pre-existing behavior and harms nothing.
func reclaimSidecars(path string) {
	if path == "" {
		return
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() > 0 {
		return
	}
	for _, suffix := range sidecarSuffixes {
		_ = os.Remove(path + suffix)
	}
}

// openSQLite creates SQLite connection with optimized settings. readIntent
// selects the read pool (openSQLiteReader) for a file-backed store.
func openSQLite(cfg *config.SQLiteConfig, readIntent bool) (*sql.DB, error) {
	// Expand path (handle ~ and environment variables)
	path := expandPath(cfg.Path)

	// A read-only open must not bring the file (or its directory) into existence:
	// creating a parent for a path that was mistyped is how a read silently
	// becomes a new empty database instead of an error.
	if cfg.ReadOnly {
		return openSQLiteReadOnly(path, cfg)
	}
	if readIntent && path != ":memory:" {
		return openSQLiteReader(path, cfg)
	}

	// Ensure parent directory exists (skip for in-memory databases)
	//
	// leftoverWAL is sampled BEFORE sql.Open, which creates the sidecars itself:
	// it is the precondition for the checkpoint below, which has nothing to fold
	// in when no -wal survives. SQLite deletes the -wal on a clean last close, so
	// this is false for a fresh file (every stateless run) and for a store the
	// previous process shut down properly — and true after a crash, which is the
	// case the checkpoint is for.
	leftoverWAL := false
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
		leftoverWAL = sidecarsPresent(path)
	}

	// Build DSN with PRAGMA settings.
	//
	// sqliteshim resolves to the pure-Go modernc.org/sqlite driver, which
	// expects connection PRAGMAs via repeated _pragma=<name>(<value>) query
	// params. The legacy mattn/go-sqlite3 form (_busy_timeout=, _journal_mode=)
	// is silently ignored by modernc, which left every connection on the
	// SQLite defaults: busy_timeout=0 and journal_mode=delete. Under
	// concurrent writers (e.g. RecordWriter batch flushes with
	// MaxOpenConns>1) that yields immediate SQLITE_BUSY failures because no
	// busy handler is installed and rollback-journal mode allows only one
	// writer. Emitting the modernc _pragma form actually applies busy_timeout
	// and WAL so writers serialize instead of failing.
	//
	// _txlock=immediate makes every transaction start with BEGIN IMMEDIATE so
	// it takes the write lock up front; combined with a real busy_timeout this
	// serializes concurrent writers rather than racing them. Both _pragma and
	// _txlock are honored by modernc; mattn (if ever selected) ignores the
	// unknown params and falls back to its own defaults harmlessly.
	// wal_autocheckpoint / temp_store / mmap_size are appended so each connection
	// keeps the WAL bounded, spills temp B-trees to memory, and uses mmap reads —
	// matching the deparos sitemap driver. Without wal_autocheckpoint the main
	// ingest DB ran on the SQLite default with no periodic reclaim path of its
	// own; the WAL could balloon to GB over a multi-day server run.
	//
	// The filename half is left exactly as it was unless it contains a character
	// the driver would misread — see sqliteDSNFilename. Every other DSN this
	// process builds therefore stays byte-identical to the one it built before,
	// which keeps the blast radius of the encoding fix on the paths that were
	// already broken.
	dsnPath, err := sqliteDSNFilename(path)
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf(
		"%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(%s)&_pragma=synchronous(%s)&_pragma=cache_size(%d)&_pragma=wal_autocheckpoint(%d)&_pragma=temp_store(memory)&_pragma=mmap_size(%d)&_txlock=immediate",
		dsnPath,
		cfg.BusyTimeout,
		cfg.JournalMode,
		cfg.Synchronous,
		cfg.CacheSize,
		sqliteWALAutocheckpoint,
		sqliteMmapSize,
	)

	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to ping SQLite: %w", err)
	}

	// Fold a WAL left over from an unclean exit back into the main database, so
	// this open starts from a compact file.
	//
	// PASSIVE, not TRUNCATE. A new CONNECTION is not a new DATABASE: `serve`'s
	// scan-on-receive poller, a `traffic` listing, or a concurrent scan can hold
	// a read lock on this file from another process, and TRUNCATE waits for every
	// one of them to let go. The only thing that wait buys is zeroing the -wal
	// file's length, which nothing on the open path needs, and which the
	// long-running process's own checkpointer still does on its timer (see
	// startWALCheckpointer). PASSIVE never waits at all.
	if strings.EqualFold(cfg.JournalMode, "WAL") && path != ":memory:" && leftoverWAL {
		_, _ = checkpointWAL(context.Background(), sqldb, "PASSIVE")
	}

	// In WAL mode, SQLite supports concurrent readers alongside a single writer.
	// Default to 8 connections so the long-running server's readers (the
	// scan-on-receive poller, status-tick counts, and read API calls) don't
	// serialize behind a too-small pool; a slow read no longer ties up a quarter
	// of the connections. For in-memory databases (:memory:), force a single
	// connection since each connection gets its own isolated database — multiple
	// connections would cause "no such table" errors as schema created on one
	// connection is invisible to others.
	maxConns := cfg.MaxOpenConns
	if maxConns <= 0 {
		maxConns = 8
	}
	if path == ":memory:" {
		maxConns = 1
	}
	sqldb.SetMaxOpenConns(maxConns)
	sqldb.SetMaxIdleConns(maxConns)

	return sqldb, nil
}

// openPostgres creates PostgreSQL connection with connection pooling. A
// read-intent pool sets default_transaction_read_only on every session, the
// server-side equivalent of SQLite's query_only.
func openPostgres(cfg *config.PostgresConfig, readIntent bool) (*sql.DB, error) {
	// Expand password from environment if needed
	password := expandEnvVars(cfg.Password)

	// Build DSN
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User,
		password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		cfg.SSLMode,
	)

	opts := []pgdriver.Option{pgdriver.WithDSN(dsn)}
	if readIntent {
		opts = append(opts, pgdriver.WithConnParams(map[string]any{
			"default_transaction_read_only": "on",
		}))
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(opts...))

	// Configure connection pool
	sqldb.SetMaxOpenConns(cfg.MaxOpenConns)
	sqldb.SetMaxIdleConns(cfg.MaxIdleConns)
	if cfg.ConnMaxLifetime != "" {
		duration, err := time.ParseDuration(cfg.ConnMaxLifetime)
		if err != nil {
			_ = sqldb.Close()
			return nil, fmt.Errorf("invalid conn_max_lifetime: %w", err)
		}
		sqldb.SetConnMaxLifetime(duration)
	}

	// Test connection
	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	return sqldb, nil
}

// Close closes database connection
func (db *DB) Close() error {
	if db.ckptStop != nil {
		db.ckptStopOnce.Do(func() { close(db.ckptStop) })
	}
	// After the handle is closed, so our own descriptors are released first.
	defer reclaimSidecars(db.ownedSidecars)

	if db.DB != nil {
		// Persist query-planner statistics before closing so the next process to
		// reopen this database (e.g. `vigolium finding`/`traffic` read commands)
		// plans dedup/finding queries against real row counts rather than the
		// SQLite defaults.
		//
		// Skipped on a read-only handle: `PRAGMA optimize` rewrites sqlite_stat1,
		// which is a write to the very artifact --read-only promises not to touch.
		// query_only(1) would refuse it anyway, so this only stops an attempt that
		// was always going to fail — but attempting it at all is the wrong shape
		// for a mode whose entire contract is "no writes".
		if db.writable() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			db.Optimize(ctx)
			cancel()
		}
		return db.DB.Close()
	}
	return nil
}

// Optimize refreshes the query-planner statistics so subsequent dedup and finding
// queries plan against real row counts. Call it after a bulk ingest phase (e.g.
// discovery) and before the heavy dedup passes; it also runs on Close and on the
// WAL checkpointer cadence. Best-effort — a failure degrades plans, never
// correctness.
//
// SQLite uses `PRAGMA optimize` (incremental: only re-analyzes tables that changed
// enough to matter). PostgreSQL analyzes just the hot ingest tables rather than
// the whole database, so a short-lived CLI run against a shared server doesn't
// trigger a blocking full-DB ANALYZE on every close.
func (db *DB) Optimize(ctx context.Context) {
	if db.DB == nil {
		return
	}
	// `PRAGMA optimize` writes sqlite_stat1. A read-only handle was opened
	// precisely so browsing a source cannot alter it, and query_only(1) would
	// reject the write anyway — leaving a debug-level error on every close of
	// every source file a glob touched. A read-intent pool is query_only too.
	if !db.writable() {
		return
	}
	stmt := "PRAGMA optimize"
	if db.driver == "postgres" {
		stmt = "ANALYZE http_records, findings"
	}
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		zap.L().Debug("query-planner optimize failed", zap.Error(err))
	}
}

// ftsIndexesBody reports whether an existing http_records_fts virtual table was
// created with the legacy body columns (raw_request/raw_response), so the caller
// knows to drop and recreate it as the slim metadata-only index. A missing table
// or query failure reports false — there is nothing to migrate.
func (db *DB) ftsIndexesBody(ctx context.Context) bool {
	var ddl string
	if err := db.QueryRowContext(ctx,
		"SELECT sql FROM sqlite_master WHERE type='table' AND name='http_records_fts'").Scan(&ddl); err != nil {
		return false
	}
	return strings.Contains(ddl, "raw_request") || strings.Contains(ddl, "raw_response")
}

// DeferRecordIndexes tells CreateSchema to leave the http_records read indexes
// uncreated, so a bulk load runs against the primary key alone. The caller MUST
// call CreateRecordIndexes once loading is done — a store left without them is
// schema-complete but plans every read as a full scan.
//
// Only for disposable stores that are filled once and then read (the --glob-db
// scratch merge). A persistent store must not defer: it is written to
// continuously, so there is no "after the load" to build them in.
func (db *DB) DeferRecordIndexes() { db.deferRecordIndexes = true }

// CreateRecordIndexes builds the http_records read indexes. Idempotent (every
// statement is IF NOT EXISTS), so calling it on a store that never deferred is
// harmless.
func (db *DB) CreateRecordIndexes(ctx context.Context) error {
	for _, ddl := range recordSecondaryIndexes {
		if _, err := db.ExecContext(ctx, db.renderDDL(ddl)); err != nil {
			return fmt.Errorf("failed to create record index: %w", err)
		}
	}
	return nil
}

// rebuildFTSIfPopulated repopulates the search index from http_records, once,
// after the index has been created or replaced.
//
// It is skipped for an empty table: on a fresh database there is nothing to
// index and the triggers cover everything from here on, so the common case pays
// one COUNT rather than a rebuild. Best-effort — a failure leaves searches
// falling back to the LIKE scan, which is slower but correct.
func (db *DB) rebuildFTSIfPopulated(ctx context.Context) {
	var rows int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM http_records").Scan(&rows); err != nil || rows == 0 {
		return
	}
	zap.L().Debug("rebuilding full-text search index", zap.Int64("records", rows))
	db.execBestEffort(ctx, "rebuild FTS index",
		"INSERT INTO http_records_fts(http_records_fts) VALUES('rebuild')")
}

// Driver returns the database driver name
func (db *DB) Driver() string {
	return db.driver
}

// Path returns the resolved SQLite file backing this handle, or "" for a driver
// that is not a single file (Postgres).
//
// It exists because DatabaseStats.Database.Path and .Size were declared and
// never filled: `db stats -j` reported `"path": "", "size": 0` for a store it
// had open and had just counted 60 records in. A consumer reading that to
// confirm WHICH database it was looking at — the whole reason the -j envelope
// carries db_path — was told nothing, in a field that looked like an answer.
func (db *DB) Path() string {
	return db.path
}

// SQLDB returns the underlying *sql.DB. Used by callers that need a pinned
// *sql.Conn for connection-scoped operations (e.g. ATTACH DATABASE during a
// SQLite-to-SQLite merge) that must run on a single physical connection.
func (db *DB) SQLDB() *sql.DB {
	return db.DB.DB
}

// ExpandPath resolves ~ and environment variables in a filesystem path using
// the same rules as the SQLite DSN builder. Exported so callers (e.g. the
// merge lock) can derive sidecar paths next to the real database file.
func ExpandPath(path string) string {
	return expandPath(path)
}

// HasFTS reports whether full-text search is available on this handle (FTS5 for
// SQLite, tsvector for PostgreSQL).
//
// It DISCOVERS the answer rather than remembering whether this process created
// the index. It used to be a plain field assigned only by SeedDefaults, which
// made the answer depend on how the handle was opened rather than on what the
// database contains: `vigolium server` seeds and reported true, every read
// command (traffic, finding, db ls) does not seed and reported false on the very
// same file. Two commands then took different query paths over one database.
//
// Discovery is lazy and cached: a handle that never searches pays nothing, and
// one that does pays a single sqlite_master lookup.
func (db *DB) HasFTS() bool {
	db.ftsMu.Lock()
	defer db.ftsMu.Unlock()
	if !db.ftsKnown {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		db.hasFTS = db.detectFTS(ctx)
		cancel()
		db.ftsKnown = true
	}
	return db.hasFTS
}

// setFTS records a known capability, for the paths that just created or dropped
// the index and need not re-discover it.
func (db *DB) setFTS(available bool) {
	db.ftsMu.Lock()
	db.hasFTS = available
	db.ftsKnown = true
	db.ftsMu.Unlock()
}

// detectFTS inspects the database for a USABLE search index.
//
// "Usable" is stricter than "present" on SQLite, and deliberately so: the index
// is an external-content FTS5 table kept current by triggers, so a table without
// its insert trigger is a table that silently stops matching anything written
// after the trigger went missing. Reporting false there costs a slower LIKE scan;
// reporting true costs correct-looking empty results.
func (db *DB) detectFTS(ctx context.Context) bool {
	if db.driver == "postgres" {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_name = 'http_records' AND column_name = 'search_vector'`).Scan(&n); err != nil {
			return false
		}
		return n > 0
	}

	if db.ftsIndexesBody(ctx) {
		// A legacy body-indexed table is migrated away by SeedDefaults; until then
		// its column set does not match the queries in query.go.
		return false
	}
	if !db.tableExists(ctx, "http_records_fts") {
		return false
	}
	var triggers int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'http_records_fts_ai'").Scan(&triggers); err != nil {
		return false
	}
	return triggers == 1
}

// ServerVersion returns the database server version string (e.g. the Postgres
// "PostgreSQL 16.1 ..." banner or the SQLite library version).
func (db *DB) ServerVersion(ctx context.Context) (string, error) {
	var query string
	switch db.driver {
	case "postgres":
		query = "SELECT version()"
	case "sqlite":
		query = "SELECT sqlite_version()"
	default:
		return "", fmt.Errorf("unsupported driver: %s", db.driver)
	}
	var version string
	if err := db.QueryRowContext(ctx, query).Scan(&version); err != nil {
		return "", err
	}
	return strings.TrimSpace(version), nil
}

// renderDDL spells a schema template (schema_ddl.go) for this handle's driver.
// Every schema statement CreateSchema issues goes through it: tables, column
// migrations and indexes.
func (db *DB) renderDDL(tmpl string) string {
	return renderDDL(db.driver, tmpl)
}

// currentSchemaVersion is the schema revision this binary expects. Bump it when
// the schema changes; gate any new one-time backfill on the version that
// introduced it (as legacyBackfillsVersion does) so it runs once per store
// rather than again on every later bump. A database already past a backfill's
// version skips it, so a current database opens in roughly constant time
// regardless of how many records it holds.
//
// History:
//
//	1  schema_meta introduced; legacy index reshaping and backfills gated.
//	2  schema_meta.min_reader_version / written_by / updated_at (the
//	   compatibility guard in schema_guard.go). Additive: min reader stays 1.
//	3  Finding lifecycle and run liveness, all additive (min reader stays 1):
//	   findings status_note/status_actor/status_updated_at, origin_record_uuid,
//	   insertion_point, payload, verification, verified_at; scans plan,
//	   heartbeat_at, current_phase, pid, runner_host, module_errors,
//	   extensions_failed; new tables finding_observations (backfilled once from
//	   each finding's (scan_uuid, found_at)), finding_status_events and
//	   oast_payloads; schema_meta.observation_history_since.
//	4  Host facts, additive (min reader stays 1): host_observations dns_mx,
//	   dns_ns, dns_txt, dns_soa, dns_caa (`vigolium dns`), fingerprint and
//	   not_found (the fingerprint phase).
//	5  host_observations.favicon (the probe phase's --favicon), additive (min
//	   reader stays 1).
//	6  Finding identity v2 (BREAKING, min reader 6): findings.last_seen_at, the
//	   finding_hash_aliases table, and a one-time re-key of insertion-point
//	   findings from the content hash to the location identity
//	   (RekeyFindingIdentities), merging rows that share it and keeping every
//	   old hash as an alias. A pre-v6 binary would hash re-detections the old
//	   way and fork every re-keyed finding, so it must not write a v6 store.
//	   Track B's scan_record_progress / scans.coverage_modules and the
//	   scans.module_stats / oast_sessions additions ride the same version.
const currentSchemaVersion = 6

// legacyBackfillsVersion is the version that gated the pre-versioning backfills
// and index reshaping in CreateSchema. A store at or past it has had them.
const legacyBackfillsVersion = 1

// observationsBackfillVersion is the version that introduced
// finding_observations. A store below it gets the one-time backfill of one
// observation per existing finding; a store at or past it was written by a
// binary that records observations on every save.
const observationsBackfillVersion = 3

// CurrentSchemaVersion exposes the schema revision this binary expects, so a
// consumer can fail loudly on drift at startup (`vigolium version --json`)
// rather than discovering it as a query error mid-run.
func CurrentSchemaVersion() int { return currentSchemaVersion }

// schemaVersion reads the recorded schema version, or 0 when unset (a fresh
// database, or one created before versioning). Requires schema_meta to exist.
func (db *DB) schemaVersion(ctx context.Context) int {
	var v int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_meta WHERE id = 1").Scan(&v); err != nil {
		return 0
	}
	return v
}

// setSchemaVersion records the schema version so later opens can skip the
// one-time backfills. Best-effort: a failure just re-runs them next open.
//
// The stored version only ever moves up. An older binary opening a database a
// newer one already migrated used to stamp its own (lower) version over it,
// which then re-ran every backfill on the next newer open and lied to any
// version check. MAX is SQLite's scalar form; Postgres spells it GREATEST.
//
// The same statement stamps the compatibility columns: min_reader_version also
// only moves up (a breaking migration raised it, and nothing may lower it
// again), and written_by names the build that set the version now recorded.
func (db *DB) setSchemaVersion(ctx context.Context, v int) {
	maxFn := "MAX"
	if db.driver == driverPostgres {
		maxFn = "GREATEST"
	}
	db.execBestEffort(ctx, "record schema version",
		`INSERT INTO schema_meta (id, version, min_reader_version, written_by, updated_at)
		 VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT (id) DO UPDATE SET
		   version = `+maxFn+`(schema_meta.version, excluded.version),
		   min_reader_version = `+maxFn+`(COALESCE(schema_meta.min_reader_version, 0), excluded.min_reader_version),
		   written_by = CASE WHEN excluded.version >= schema_meta.version THEN excluded.written_by ELSE schema_meta.written_by END,
		   updated_at = excluded.updated_at`,
		v, minReaderVersion, currentBinaryVersion())
}

// CreateSchema creates all database tables and indexes if they don't exist.
//
// It is a no-op on a read-only handle. The read commands call it on open to
// self-heal a fresh project database; against a source opened --read-only that
// would be a schema write to someone else's evidence, and a source genuinely
// missing the tables surfaces as a query error rather than being silently
// migrated into the current shape.
//
// It refuses (SchemaTooNewError) a store a newer binary has stamped: DDL and
// backfills written for an older schema are not safe to run against one this
// binary does not know.
func (db *DB) CreateSchema(ctx context.Context) error {
	if !db.writable() {
		// A read-only handle cannot be migrated — `mode=ro` refuses DDL, and a
		// read-intent pool is query_only — so the best it can do is report a
		// schema it will not be able to query. Without this the caller's first
		// SELECT fails with a bare "no such column: r.surface_score", which names
		// a symptom and no remedy.
		return db.checkSchemaCurrent(ctx)
	}
	if err := db.guardWriteDB(ctx); err != nil {
		return err
	}
	zap.L().Debug("Initializing database tables")
	for _, ddl := range schemaTables {
		if _, err := db.ExecContext(ctx, db.renderDDL(ddl)); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// A database already at currentSchemaVersion has had the one-time backfills and
	// legacy-index reshaping below applied, so skip them — they scan/rewrite whole
	// tables and would otherwise run on every open. Cheap idempotent DDL (CREATE
	// TABLE/INDEX IF NOT EXISTS, ADD COLUMN) still runs unconditionally so the
	// schema stays self-healing.
	//
	// Gated on legacyBackfillsVersion, not currentSchemaVersion: these are the
	// version-1 migrations, and a v1 store opened by a later binary has had them.
	// Gating on the current version re-ran every one of them — a covering-index
	// rebuild and whole-table backfills — on each schema bump.
	storedVersion := db.schemaVersion(ctx)
	schemaCurrent := storedVersion >= legacyBackfillsVersion

	// Drop old indexes before creating the correct ones (migration for existing
	// databases). Gated on schema version: once applied, the indexes already have
	// their new shape, and re-dropping idx_records_dedup here would force a full
	// covering-index rebuild (O(records)) on every open. Must run before CREATE
	// UNIQUE INDEX so the unconditional unique index survives. idx_findings_hash_unique
	// was a global UNIQUE(finding_hash) — superseded by the project-scoped
	// idx_findings_project_hash_unique below; dropping it lets the same finding_hash
	// coexist across projects.
	if !schemaCurrent {
		db.execBestEffort(ctx, "drop legacy index idx_findings_hash", "DROP INDEX IF EXISTS idx_findings_hash")
		db.execBestEffort(ctx, "drop legacy index idx_findings_hash_unique", "DROP INDEX IF EXISTS idx_findings_hash_unique")

		// idx_records_dedup was (project_uuid, method, hostname, path); it is
		// recreated below as a covering index that also includes url, request_hash,
		// and uuid so findDuplicateRecord resolves without a table fetch. Drop the
		// old definition so the CREATE INDEX IF NOT EXISTS below actually applies on
		// existing databases (IF NOT EXISTS would otherwise keep the stale shape).
		db.execBestEffort(ctx, "drop legacy index idx_records_dedup", "DROP INDEX IF EXISTS idx_records_dedup")

		// Drop old single-column indexes superseded by project-aware composites
		oldIndexes := []string{
			"idx_records_hostname", "idx_records_method", "idx_records_status_code",
			"idx_records_sent_at", "idx_records_host_method_status", "idx_records_scheme_host_port",
			"idx_records_risk_score", "idx_records_created_at_uuid",
			"idx_findings_module_id", "idx_findings_severity", "idx_findings_found_at", "idx_findings_scan_uuid",
			"idx_scans_status", "idx_scans_started_at",
			"idx_scopes_enabled_priority",
			"idx_oast_interactions_scan_uuid",
			"idx_scan_logs_scan_uuid",
		}
		for _, idx := range oldIndexes {
			db.execBestEffort(ctx, "drop legacy index "+idx, "DROP INDEX IF EXISTS "+idx)
		}
	}

	// Column migrations for existing databases — MUST run before the index loop
	// (moved below). Several indexes reference columns added here, e.g.
	// idx_records_norm_hash → http_records.response_norm_hash. The index loop
	// aborts CreateSchema on the first error, so building a new column's index
	// before the column exists fails schema init entirely and leaves repo nil.
	db.runColumnMigrations(ctx)

	// A Postgres store created before the per-dialect templates may hold bool
	// columns as INTEGER, which no CREATE/ADD COLUMN can fix and every bool
	// write fails on (schema_pg_bool.go). Fatal: a store left that way cannot
	// save records.
	if err := db.convertLegacyBoolColumns(ctx); err != nil {
		return fmt.Errorf("failed to migrate bool columns: %w", err)
	}

	// Create indexes now that all column migrations above have run — some indexes
	// reference newly added columns (e.g. idx_records_norm_hash → response_norm_hash).
	for _, ddl := range schemaIndexes {
		if _, err := db.ExecContext(ctx, db.renderDDL(ddl)); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}
	if !db.deferRecordIndexes {
		if err := db.CreateRecordIndexes(ctx); err != nil {
			return err
		}
	}

	// One-time O(rows) backfills. Gated on schema version: each scans a whole table
	// (or every finding's JSON), so re-running them on every open makes startup
	// scale with database size. New rows are written with correct values by the
	// write paths, so these only reconcile pre-versioning legacy data.
	if !schemaCurrent {
		// Backfill empty project_uuid values — Bun ORM inserts explicit empty strings
		// which bypass the column DEFAULT, so rows created before ProjectUUID was
		// propagated through all code paths end up with project_uuid = ''.
		for _, table := range projectUUIDMigrationTables {
			db.execBestEffort(ctx, "backfill project_uuid on "+table,
				fmt.Sprintf("UPDATE %s SET project_uuid = ? WHERE project_uuid = ''", table),
				DefaultProjectUUID)
		}

		// Migrate legacy finding statuses: 'open' and 'confirmed' both collapse to
		// 'triaged' in the current state model (see models.Status* constants).
		db.execBestEffort(ctx, "migrate legacy finding statuses",
			"UPDATE findings SET status = ? WHERE status IN (?, ?)",
			StatusTriaged, "open", "confirmed")

		// Backfill finding_records from existing JSONB data (idempotent)
		if db.driver == "postgres" {
			db.execBestEffort(ctx, "backfill finding_records", `
				INSERT INTO finding_records (finding_id, record_uuid)
				SELECT f.id, je
				FROM findings f, jsonb_array_elements_text(f.http_record_uuids::jsonb) AS je
				WHERE f.http_record_uuids IS NOT NULL AND f.http_record_uuids != '' AND f.http_record_uuids != '[]'
				ON CONFLICT DO NOTHING
			`)
		} else {
			db.execBestEffort(ctx, "backfill finding_records", `
				INSERT OR IGNORE INTO finding_records (finding_id, record_uuid)
				SELECT f.id, je.value
				FROM findings f, json_each(f.http_record_uuids) AS je
			`)
		}
	}

	// Schema v3: one observation per existing finding, so a scan diff over
	// pre-v3 history sees at least each finding's most recent observer. Unlike
	// the best-effort legacy backfills this one fails the migration: a store
	// stamped v3 without it would answer "never observed" for every old finding,
	// and the version gate means it would never be retried.
	if storedVersion < observationsBackfillVersion {
		if err := db.backfillFindingObservations(ctx); err != nil {
			return err
		}
	}

	// Schema v6: re-key insertion-point findings to identity v2. Fatal like the
	// v3 backfill: a store stamped v6 without it would fork every re-detected
	// finding into a second row, and the version gate would never retry it.
	if storedVersion < identityV2Version {
		if _, err := db.RekeyFindingIdentities(ctx, ""); err != nil {
			return err
		}
	}

	// Known-issue-scan evidence used to be stored with source "spa", which no
	// evidence filter knew, so it was rescanned as input. Relabel it once
	// (schema v6; idempotent: nothing writes "spa" any more).
	if storedVersion < identityV2Version {
		db.execBestEffort(ctx, "relabel known-issue evidence records",
			"UPDATE http_records SET source = ? WHERE source = ?", RecordSourceFinding, legacyKISEvidenceSource)
	}

	// Record the version so the next open can skip the gated work above. Done last
	// so a failure partway through leaves the version unset and the migrations retry.
	db.setSchemaVersion(ctx, currentSchemaVersion)

	return nil
}

// SeedDefaults creates the default user and project if they don't exist.
// This is called during initialization to ensure CLI has a working project context.
func (db *DB) SeedDefaults(ctx context.Context) error {
	if db.driver == "postgres" {
		db.execBestEffort(ctx, "seed default user",
			"INSERT INTO users (uuid, name, email, created_at, updated_at) VALUES (?, ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (uuid) DO NOTHING",
			DefaultUserUUID, "vigolium-admin")
		db.execBestEffort(ctx, "seed default project",
			"INSERT INTO projects (uuid, name, description, owner_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (uuid) DO NOTHING",
			DefaultProjectUUID, "Default Project", "Auto-created default project", DefaultUserUUID)
	} else {
		db.execBestEffort(ctx, "seed default user",
			"INSERT OR IGNORE INTO users (uuid, name, email, created_at, updated_at) VALUES (?, ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
			DefaultUserUUID, "vigolium-admin")
		db.execBestEffort(ctx, "seed default project",
			"INSERT OR IGNORE INTO projects (uuid, name, description, owner_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
			DefaultProjectUUID, "Default Project", "Auto-created default project", DefaultUserUUID)
	}

	// Create FTS5 index for full-text search on HTTP records (SQLite only).
	//
	// Only the cheap metadata columns (url, path, hostname) are indexed. The
	// large raw_request/raw_response blobs are deliberately NOT in the FTS index:
	// indexing them forced every record INSERT to CAST both blobs to TEXT and
	// re-tokenize multi-KB bodies inline in the write transaction — roughly
	// doubling steady-state ingest write volume purely to accelerate the rare
	// body/header search. Body/header searches now use the CAST(...) LIKE scan in
	// query.go (applyRawCorpusSearch); see also the legacy-table cleanup below
	// which drops a previously body-indexed FTS so the slim definition applies.
	if db.driver != "postgres" {
		// Whether the index has to be (re)populated is decided BEFORE any DDL
		// runs, because both answers stop being observable once it has.
		//
		// An external-content FTS5 table is created EMPTY: its rows come from the
		// triggers below, which only fire on writes that happen afterwards. So a
		// database that already holds traffic — one upgrading from no index, or
		// from the legacy body-indexed one — gets a table that matches nothing
		// ever written before this moment, while HasFTS reports the index as
		// usable. Searches then return zero hits and no error. The one-time
		// 'rebuild' below is what makes the index describe the table it indexes.
		legacyBodyIndex := db.ftsIndexesBody(ctx)
		ftsExisted := db.tableExists(ctx, "http_records_fts")

		if legacyBodyIndex {
			// Only drop the triggers when the table they write to is going away.
			// Dropping them on every seed would leave a window — however short —
			// in which concurrent inserts land in http_records and never reach
			// the index, permanently invisible to search.
			db.execBestEffort(ctx, "drop legacy FTS insert trigger", "DROP TRIGGER IF EXISTS http_records_fts_ai")
			db.execBestEffort(ctx, "drop legacy FTS delete trigger", "DROP TRIGGER IF EXISTS http_records_fts_ad")
			db.execBestEffort(ctx, "drop legacy FTS update trigger", "DROP TRIGGER IF EXISTS http_records_fts_au")
			db.execBestEffort(ctx, "drop legacy body-indexed FTS table", "DROP TABLE IF EXISTS http_records_fts")
		}

		_, ftsErr := db.ExecContext(ctx, `
			CREATE VIRTUAL TABLE IF NOT EXISTS http_records_fts USING fts5(
				url,
				path,
				hostname,
				content=http_records,
				content_rowid=rowid,
				tokenize='porter unicode61'
			)`)
		if ftsErr != nil {
			zap.L().Debug("FTS5 not available, falling back to CAST/LIKE searches", zap.Error(ftsErr))
			db.setFTS(false)
		} else {
			ftsTrigs := []string{
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ai AFTER INSERT ON http_records BEGIN
					INSERT INTO http_records_fts(rowid, url, path, hostname)
					VALUES (new.rowid, new.url, new.path, new.hostname);
				END`,
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ad AFTER DELETE ON http_records BEGIN
					INSERT INTO http_records_fts(http_records_fts, rowid, url, path, hostname)
					VALUES ('delete', old.rowid, old.url, old.path, old.hostname);
				END`,
				// The indexed columns are mutable — generic CRUD and the server's
				// record update can rewrite url/path/hostname — and without this
				// trigger the index kept the OLD tokens forever: searching the
				// value now stored found nothing, searching the value that was
				// replaced found the record. Delete-then-insert is the documented
				// way to restate a row in an external-content table.
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_au
				 AFTER UPDATE OF url, path, hostname ON http_records BEGIN
					INSERT INTO http_records_fts(http_records_fts, rowid, url, path, hostname)
					VALUES ('delete', old.rowid, old.url, old.path, old.hostname);
					INSERT INTO http_records_fts(rowid, url, path, hostname)
					VALUES (new.rowid, new.url, new.path, new.hostname);
				END`,
			}
			triggersOK := true
			for _, trig := range ftsTrigs {
				if _, err := db.ExecContext(ctx, trig); err != nil {
					zap.L().Debug("Failed to create FTS trigger", zap.Error(err))
					triggersOK = false
				}
			}

			// Rebuild only on the transition — never on an already-current
			// database, where it would re-tokenize every row on every open and
			// make startup scale with corpus size.
			if triggersOK && (legacyBodyIndex || !ftsExisted) {
				db.rebuildFTSIfPopulated(ctx)
			}

			// The capability is published last, and only if the triggers that
			// keep it current are in place. Announcing a half-built index is how
			// a search returns nothing and looks like an answer.
			db.setFTS(triggersOK)
		}
	} else {
		// PostgreSQL: use tsvector with GIN index for full-text search.
		// to_tsvector rejects inputs over ~1 MiB, so cap the encoded raw
		// columns well under that to keep INSERT of large responses safe.
		_, pgErr := db.ExecContext(ctx, `
			ALTER TABLE http_records
			ADD COLUMN IF NOT EXISTS search_vector tsvector
			GENERATED ALWAYS AS (
				to_tsvector('english',
					coalesce(url, '') || ' ' ||
					coalesce(path, '') || ' ' ||
					coalesce(hostname, '') || ' ' ||
					coalesce(left(encode(raw_request, 'escape'), 524288), '') || ' ' ||
					coalesce(left(encode(raw_response, 'escape'), 524288), '')
				)
			) STORED`)
		if pgErr != nil {
			zap.L().Debug("PostgreSQL tsvector not available", zap.Error(pgErr))
		} else {
			db.execBestEffort(ctx, "create http_records search index",
				"CREATE INDEX IF NOT EXISTS idx_http_records_search ON http_records USING GIN (search_vector)")
			db.setFTS(true)
		}
	}

	return nil
}

// execBestEffort runs a best-effort migration or maintenance statement,
// logging (rather than propagating) any error. Used for idempotent backfills,
// legacy-index cleanup, and default seeding where a failure must not abort
// startup but should still be diagnosable.
func (db *DB) execBestEffort(ctx context.Context, op, query string, args ...any) {
	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		zap.L().Debug("best-effort statement failed", zap.String("op", op), zap.Error(err))
	}
}

// addColumnIfNotExists attempts to add a column, ignoring errors if it already exists.
func (db *DB) addColumnIfNotExists(ctx context.Context, table, column, definition string) {
	ddl := db.renderDDL(columnMigrationDDL(columnMigration{table, column, definition}))
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		// Ignore "duplicate column" errors (SQLite: "duplicate column name", Postgres: "already exists")
		errMsg := err.Error()
		if !strings.Contains(errMsg, "duplicate column") && !strings.Contains(errMsg, "already exists") {
			zap.L().Warn("Failed to add column", zap.String("column", column), zap.Error(err))
		}
	}
}

// projectUUIDMigrationTables are the tables that predate multi-tenancy and so
// need project_uuid added (and backfilled) on an existing database.
//
// Deliberately NARROWER than projectOwnedTables: analysis_artifacts,
// agentic_scans and authentication_hostnames are project-scoped too, but they
// were created with the column in their own CREATE TABLE, so they need neither
// the ALTER nor the O(rows) backfill. Widening this to projectOwnedTables would
// add a full-table UPDATE per open for three tables that cannot need it.
var projectUUIDMigrationTables = []string{
	"scans", "http_records", "findings", "scopes", "oast_interactions", "scan_logs",
}

// runColumnMigrations applies every additive column migration.
func (db *DB) runColumnMigrations(ctx context.Context) {
	for _, m := range columnMigrations {
		db.addColumnIfNotExists(ctx, m.Table, m.Column, m.Def)
	}
}

// ErrSchemaOutdated marks a database written by an older vigolium that this
// handle cannot migrate because it was opened read-only. It is a distinct error
// because it is FATAL to the command — every query that follows would fail on a
// missing column — whereas a migration failure on a writable handle is
// best-effort and worth only a warning.
//
// A read-intent open reports it as *SchemaOutdatedError (remedy: `vigolium db
// migrate`); a --read-only evidence open wraps it with that mode's remedy.
var ErrSchemaOutdated = errors.New("database schema is older than this vigolium")

// EnsureSchemaCurrent brings an existing database up to date, doing NOTHING when
// it already is.
//
// The "do nothing" path is the whole point. CreateSchema issues DDL, and DDL
// takes SQLite's WRITE lock — so calling it unconditionally on every open makes
// every read command queue behind any concurrent writer for up to busy_timeout
// (60s by default). Detecting staleness first is a read-only question, so the
// common case takes no lock at all.
//
// A read-only handle cannot be migrated (mode=ro refuses DDL); CreateSchema's
// own read-only branch turns that into ErrSchemaOutdated naming the missing
// columns, so it is reached through the same call rather than special-cased
// here.
//
// Indexes and tables are deliberately not part of the check: only a missing
// COLUMN makes the read commands this serves fail outright, and a read command
// meeting an old file wants the cheapest question that unblocks it.
//
// That makes this the WEAKER of the package's two readiness checks, and it is
// not the one to reach for when the answer gates a write workload — a missing
// table or a missing UNIQUE index passes it. See EnsureSchemaReady, which checks
// every object CreateSchema creates and is what the scan entry points use now
// that they no longer run CreateSchema unconditionally.
func (db *DB) EnsureSchemaCurrent(ctx context.Context) error {
	if !db.writable() {
		// Nothing to migrate through this handle: report what it cannot read.
		return db.checkSchemaCurrent(ctx)
	}
	if err := db.guardWriteDB(ctx); err != nil {
		return err
	}
	missing, err := db.missingColumns(ctx)
	if err == nil && len(missing) == 0 {
		return nil
	}
	return db.CreateSchema(ctx)
}

// HasVigoliumSchema reports whether this store has been initialized as a
// vigolium database, by the presence of the core table every read touches.
//
// It is the question "is this the right file?", which is NOT the same as "does
// it have rows": a foreign SQLite file and a scanned target both open cleanly,
// and only this distinguishes them before vigolium's tables get created inside
// the former.
func (db *DB) HasVigoliumSchema(ctx context.Context) bool {
	return db.tableExists(ctx, coreTableName)
}

// checkSchemaCurrent reports a read-only handle's missing columns as an error
// naming them and how to proceed, or nil when it is current.
//
// Without it the caller's first SELECT fails with a bare "no such column:
// r.surface_score" — a symptom naming no remedy. A brand-new/empty file is not
// "outdated": it has no tables at all, and every read of it correctly returns
// nothing.
func (db *DB) checkSchemaCurrent(ctx context.Context) error {
	// A store this binary cannot read at all is refused before anything else:
	// its columns may well look complete, which is exactly the trap.
	if info, err := db.SchemaInfo(ctx); err == nil {
		if err := guardRead(info); err != nil {
			return err
		}
	}
	missing, err := db.missingColumns(ctx)
	if err != nil || len(missing) == 0 {
		return nil
	}
	if db.reader {
		return &SchemaOutdatedError{DBVersion: db.schemaVersion(ctx), Missing: missing}
	}
	return fmt.Errorf("%w and --read-only cannot migrate it (missing: %s)\n"+
		"  drop --read-only to upgrade it in place, or copy the file first if it must not change",
		ErrSchemaOutdated, strings.Join(missing, ", "))
}

// missingColumns reports which entries of columnMigrations this database lacks,
// as "table.column". Read-only: it never takes a write lock.
//
// A returned error means the catalog could not be read at all (an empty or
// unopenable file); callers treat that as "cannot tell" rather than as "stale",
// since a fresh database legitimately has no tables yet.
func (db *DB) missingColumns(ctx context.Context) ([]string, error) {
	// An absent core table means a fresh (or empty) file: it needs the full
	// CreateSchema, and being new it has no concurrent writer to contend with.
	if !db.tableExists(ctx, coreTableName) {
		return nil, errSchemaNotInitialized
	}
	return db.missingColumnsFrom(ctx, nil)
}

// missingColumnsFrom is missingColumns for a caller that has already
// established the core table exists — it skips that probe rather than repeating
// it. `present` is only consulted to skip the probe; pass nil when unknown.
func (db *DB) missingColumnsFrom(ctx context.Context, present map[string]bool) ([]string, error) {
	if present != nil && !present[coreTableName] {
		return nil, errSchemaNotInitialized
	}

	existing, err := listAllColumns(ctx, db)
	if err != nil {
		return nil, err
	}

	var missing []string
	for _, m := range columnMigrations {
		// A table that does not exist yet reports no columns, so every one of
		// its migrations lands in `missing` and CreateSchema creates it.
		if !existing[m.Table][m.Column] {
			missing = append(missing, m.Table+"."+m.Column)
		}
	}
	return missing, nil
}

// coreTableName is the table whose presence distinguishes an initialized
// vigolium store from a fresh file or a foreign SQLite database. Named once
// because three separate checks key off it.
const coreTableName = "http_records"

// errSchemaNotInitialized marks a database with no core table — a fresh file,
// not a stale one.
var errSchemaNotInitialized = errors.New("schema not initialized")

// tableExists reports whether a table is present.
func (db *DB) tableExists(ctx context.Context, table string) bool {
	var n int
	err := db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE 1=0", table)).Scan(&n)
	return err == nil
}

// expandPath handles ~ expansion and environment variables
func expandPath(path string) string {
	// Expand environment variables
	path = expandEnvVars(path)

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		path = filepath.Join(home, path[2:])
	}

	return path
}

// expandEnvVars replaces ${VAR} or $VAR with environment variable values
func expandEnvVars(s string) string {
	return os.ExpandEnv(s)
}

// debugQueryHook logs SQL queries in debug mode
type debugQueryHook struct{}

func (h debugQueryHook) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

func (h debugQueryHook) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	query := event.Query
	// Skip logging DDL statements and noisy internal queries to reduce noise
	if strings.HasPrefix(query, "CREATE ") || strings.HasPrefix(query, "ALTER ") ||
		strings.Contains(query, "finding_records") {
		return
	}
	if len(query) > 500 {
		query = query[:500] + "..."
	}
	zap.L().Debug("SQL query executed",
		zap.String("query", query),
		zap.Duration("duration", time.Since(event.StartTime)),
	)
}
