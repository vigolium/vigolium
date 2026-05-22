package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// DB wraps bun.DB with additional metadata
type DB struct {
	*bun.DB
	driver string
	hasFTS bool // true if FTS5 (SQLite) or tsvector (Postgres) is available
}

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

	switch cfg.Driver {
	case "sqlite":
		var err error
		sqldb, err = openSQLite(&cfg.SQLite)
		if err != nil {
			return nil, fmt.Errorf("failed to open SQLite: %w", err)
		}
		bunDB = bun.NewDB(sqldb, sqlitedialect.New())
		driver = "sqlite"

	case "postgres":
		var err error
		sqldb, err = openPostgres(&cfg.Postgres)
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL: %w", err)
		}
		bunDB = bun.NewDB(sqldb, pgdialect.New())
		driver = "postgres"

	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	db := &DB{
		DB:     bunDB,
		driver: driver,
	}

	// Enable query logging in debug mode
	if zap.L().Core().Enabled(zap.DebugLevel) {
		db.AddQueryHook(debugQueryHook{})
	}

	return db, nil
}

// NewDBFromBun wraps an existing bun.DB for use in tests or external tooling.
func NewDBFromBun(bunDB *bun.DB, driver string) *DB {
	return &DB{DB: bunDB, driver: driver}
}

// openSQLite creates SQLite connection with optimized settings
func openSQLite(cfg *config.SQLiteConfig) (*sql.DB, error) {
	// Expand path (handle ~ and environment variables)
	path := expandPath(cfg.Path)

	// Ensure parent directory exists (skip for in-memory databases)
	if path != ":memory:" {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
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
	dsn := fmt.Sprintf(
		"%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(%s)&_pragma=synchronous(%s)&_pragma=cache_size(%d)&_txlock=immediate",
		path,
		cfg.BusyTimeout,
		cfg.JournalMode,
		cfg.Synchronous,
		cfg.CacheSize,
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

	// In WAL mode, SQLite supports concurrent readers alongside a single writer.
	// Default to 4 connections to allow read parallelism.
	// For in-memory databases (:memory:), force a single connection since each
	// connection gets its own isolated database — multiple connections would cause
	// "no such table" errors as schema created on one connection is invisible to others.
	maxConns := cfg.MaxOpenConns
	if maxConns <= 0 {
		maxConns = 4
	}
	if path == ":memory:" {
		maxConns = 1
	}
	sqldb.SetMaxOpenConns(maxConns)
	sqldb.SetMaxIdleConns(maxConns)

	return sqldb, nil
}

// openPostgres creates PostgreSQL connection with connection pooling
func openPostgres(cfg *config.PostgresConfig) (*sql.DB, error) {
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

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))

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
	if db.DB != nil {
		return db.DB.Close()
	}
	return nil
}

// Driver returns the database driver name
func (db *DB) Driver() string {
	return db.driver
}

// HasFTS returns true if full-text search is available (FTS5 for SQLite, tsvector for PostgreSQL).
func (db *DB) HasFTS() bool {
	return db.hasFTS
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

// adaptDDL rewrites SQLite-specific DDL for PostgreSQL when needed.
func (db *DB) adaptDDL(ddl string) string {
	if db.driver != "postgres" {
		return ddl
	}
	ddl = strings.ReplaceAll(ddl, "INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
	ddl = strings.ReplaceAll(ddl, "BLOB", "BYTEA")
	// SQLite uses INTEGER for booleans; PostgreSQL needs BOOLEAN
	ddl = strings.ReplaceAll(ddl, "has_response INTEGER NOT NULL DEFAULT 0", "has_response BOOLEAN NOT NULL DEFAULT FALSE")
	ddl = strings.ReplaceAll(ddl, "is_authenticated INTEGER NOT NULL DEFAULT 0", "is_authenticated BOOLEAN NOT NULL DEFAULT FALSE")
	ddl = strings.ReplaceAll(ddl, "enabled INTEGER NOT NULL DEFAULT 1", "enabled BOOLEAN NOT NULL DEFAULT TRUE")
	return ddl
}

// CreateSchema creates all database tables and indexes if they don't exist
func (db *DB) CreateSchema(ctx context.Context) error {
	tables := []string{
		// Multi-tenancy: users and projects
		`CREATE TABLE IF NOT EXISTS users (
			uuid TEXT PRIMARY KEY NOT NULL,
			email TEXT,
			name TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS projects (
			uuid TEXT PRIMARY KEY NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			owner_uuid TEXT,
			config_path TEXT,
			tags TEXT,
			default_target TEXT,
			last_scan_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			uuid TEXT PRIMARY KEY NOT NULL,
			project_uuid TEXT NOT NULL,
			name TEXT,
			description TEXT,
			status TEXT NOT NULL DEFAULT 'running',
			target TEXT,
			modules TEXT,
			threads INTEGER DEFAULT 0,
			profile TEXT,
			source_path TEXT,
			source_type TEXT,
			tags TEXT,
			triggered_by TEXT,
			agentic_scan_uuid TEXT,
			http_record_uuid TEXT,
			scan_source TEXT,
			scan_mode TEXT,
			start_cursor_at TIMESTAMP,
			start_cursor_uuid TEXT,
			cursor_at TIMESTAMP,
			cursor_uuid TEXT,
			processed_count INTEGER DEFAULT 0,
			started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at TIMESTAMP,
			duration_ms INTEGER DEFAULT 0,
			total_requests INTEGER DEFAULT 0,
			total_findings INTEGER DEFAULT 0,
			critical_count INTEGER DEFAULT 0,
			high_count INTEGER DEFAULT 0,
			medium_count INTEGER DEFAULT 0,
			low_count INTEGER DEFAULT 0,
			info_count INTEGER DEFAULT 0,
			suspect_count INTEGER DEFAULT 0,
			error_message TEXT,
			storage_url TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS http_records (
			uuid TEXT PRIMARY KEY NOT NULL,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			scheme TEXT NOT NULL,
			hostname TEXT NOT NULL,
			port INTEGER NOT NULL,
			ip TEXT,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			url TEXT NOT NULL,
			http_version TEXT NOT NULL,
			request_content_type TEXT,
			request_content_length INTEGER DEFAULT 0,
			raw_request BLOB,
			request_hash TEXT NOT NULL,
			request_authorization TEXT,
			status_code INTEGER DEFAULT 0,
			status_phrase TEXT,
			response_http_version TEXT,
			response_content_type TEXT,
			response_content_length INTEGER DEFAULT 0,
			raw_response BLOB,
			response_hash TEXT,
			response_time_ms INTEGER DEFAULT 0,
			response_words INTEGER DEFAULT 0,
			has_response INTEGER NOT NULL DEFAULT 0,
			response_title TEXT,
			parameters TEXT,
			sent_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			received_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			source TEXT DEFAULT '',
			technology TEXT,
			content_hash TEXT,
			is_authenticated INTEGER NOT NULL DEFAULT 0,
			parent_uuid TEXT,
			remarks TEXT,
			risk_score INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			http_record_uuids TEXT NOT NULL,
			scan_uuid TEXT,
			agentic_scan_uuid TEXT,
			url TEXT,
			hostname TEXT,
			module_id TEXT NOT NULL,
			module_name TEXT NOT NULL,
			module_type TEXT DEFAULT '',
			finding_source TEXT DEFAULT '',
			module_short TEXT DEFAULT '',
			description TEXT,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL DEFAULT 'firm',
			tags TEXT,
			status TEXT DEFAULT 'triaged',
			remediation TEXT,
			cwe_id TEXT,
			cvss_score REAL DEFAULT 0,
			source_file TEXT,
			repo_name TEXT,
			matched_at TEXT,
			extracted_results TEXT,
			additional_evidence TEXT,
			request TEXT,
			response TEXT,
			finding_hash TEXT NOT NULL,
			found_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS finding_records (
			finding_id INTEGER NOT NULL,
			record_uuid TEXT NOT NULL,
			PRIMARY KEY (finding_id, record_uuid)
		)`,
		`CREATE TABLE IF NOT EXISTS scopes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			rule_type TEXT NOT NULL,
			host_pattern TEXT,
			path_pattern TEXT,
			content_type_pattern TEXT,
			methods TEXT,
			ports TEXT,
			schemes TEXT,
			priority INTEGER NOT NULL DEFAULT 100,
			enabled INTEGER NOT NULL DEFAULT 1,
			hit_count INTEGER DEFAULT 0,
			last_matched_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS oast_interactions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			unique_id TEXT NOT NULL,
			full_id TEXT NOT NULL,
			protocol TEXT NOT NULL,
			q_type TEXT,
			raw_request TEXT,
			raw_response TEXT,
			remote_address TEXT,
			interacted_at TIMESTAMP NOT NULL,
			target_url TEXT,
			parameter_name TEXT,
			injection_type TEXT,
			module_id TEXT,
			finding_id INTEGER,
			payload TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS agentic_scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL UNIQUE,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			mode TEXT NOT NULL,
			agent_name TEXT NOT NULL,
			input_raw TEXT,
			input_type TEXT,
			target_url TEXT,
			vuln_type TEXT,
			module_names TEXT,
			template_id TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			current_phase TEXT,
			phases_run TEXT,
			finding_count INTEGER DEFAULT 0,
			record_count INTEGER DEFAULT 0,
			saved_count INTEGER DEFAULT 0,
			source_path TEXT,
			source_type TEXT,
			token_usage TEXT,
			retry_count INTEGER DEFAULT 0,
			parent_run_uuid TEXT,
			input_record_count INTEGER DEFAULT 0,
			attack_plan TEXT,
			triage_result TEXT,
			prompt_sent TEXT,
			agent_raw_output TEXT,
			error_message TEXT,
			result_json TEXT,
			storage_url TEXT,
			session_id TEXT,
			session_dir TEXT,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			duration_ms INTEGER DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS authentication_hostnames (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT,
			hostname TEXT NOT NULL,
			session_name TEXT NOT NULL,
			session_role TEXT DEFAULT '',
			position INTEGER DEFAULT 0,
			session_token TEXT,
			headers TEXT,
			login_url TEXT,
			login_method TEXT,
			login_content_type TEXT,
			login_body TEXT,
			login_request TEXT,
			login_response TEXT,
			extract_rules TEXT,
			source TEXT DEFAULT '',
			hydrated_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS scan_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			scan_uuid TEXT NOT NULL,
			level TEXT NOT NULL,
			phase TEXT,
			message TEXT NOT NULL,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	zap.L().Debug("Initializing database tables")
	for _, ddl := range tables {
		if _, err := db.ExecContext(ctx, db.adaptDDL(ddl)); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	indexes := []string{
		// -- http_records: project-aware composite indexes --
		"CREATE INDEX IF NOT EXISTS idx_records_project_hostname ON http_records(project_uuid, hostname)",
		"CREATE INDEX IF NOT EXISTS idx_records_project_created_uuid ON http_records(project_uuid, created_at, uuid)",
		"CREATE INDEX IF NOT EXISTS idx_records_project_sent_at ON http_records(project_uuid, sent_at)",
		"CREATE INDEX IF NOT EXISTS idx_records_project_host_method_status ON http_records(project_uuid, hostname, method, status_code)",
		"CREATE INDEX IF NOT EXISTS idx_records_project_scheme_host_port ON http_records(project_uuid, scheme, hostname, port)",
		"CREATE INDEX IF NOT EXISTS idx_records_project_risk_score ON http_records(project_uuid, risk_score)",
		"CREATE INDEX IF NOT EXISTS idx_records_dedup ON http_records(project_uuid, method, hostname, path)",
		"CREATE INDEX IF NOT EXISTS idx_records_request_hash ON http_records(request_hash)",
		"CREATE INDEX IF NOT EXISTS idx_records_response_hash ON http_records(response_hash)",

		// -- http_records: scan_uuid index --
		"CREATE INDEX IF NOT EXISTS idx_records_project_scan ON http_records(project_uuid, scan_uuid)",

		// -- http_records: source-filtered cursor scan (scan-on-receive) --
		// Supports WHERE source IN (...) AND created_at > cursor filters in
		// DBInputSource.fetchNextBatch and Repository.CountRecordsAfterCursorBySource.
		"CREATE INDEX IF NOT EXISTS idx_records_project_source_created ON http_records(project_uuid, source, created_at, uuid)",

		// -- findings: project-aware composite indexes --
		"CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_uuid, severity)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_module ON findings(project_uuid, module_id)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_found_at ON findings(project_uuid, found_at)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_module_type ON findings(project_uuid, module_type)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_finding_source ON findings(project_uuid, finding_source)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_scan ON findings(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_hostname ON findings(project_uuid, hostname)",
		// Sparse (nullzero column) — used by agent end-of-run summaries and
		// webhook notifications to count findings per agentic-scan run.
		"CREATE INDEX IF NOT EXISTS idx_findings_agentic_scan ON findings(agentic_scan_uuid)",
		// Dedup is scoped per project: the same finding_hash may legitimately
		// recur across projects without one project's finding suppressing
		// another's. Backs ON CONFLICT (project_uuid, finding_hash).
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_project_hash_unique ON findings(project_uuid, finding_hash)",

		// -- finding_records --
		"CREATE INDEX IF NOT EXISTS idx_finding_records_record_uuid ON finding_records(record_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_finding_records_finding_id ON finding_records(finding_id)",

		// -- scans --
		"CREATE INDEX IF NOT EXISTS idx_scans_project_status ON scans(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_scans_project_created ON scans(project_uuid, created_at)",

		// -- scopes --
		"CREATE INDEX IF NOT EXISTS idx_scopes_project_enabled_priority ON scopes(project_uuid, enabled, priority)",

		// -- oast_interactions --
		"CREATE INDEX IF NOT EXISTS idx_oast_project_scan ON oast_interactions(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_oast_interactions_unique_id ON oast_interactions(unique_id)",

		// -- agentic_scans --
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_uuid ON agentic_scans(uuid)",
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_status ON agentic_scans(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_project_created ON agentic_scans(project_uuid, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_agentic_scans_scan ON agentic_scans(scan_uuid)",

		// -- authentication_hostnames --
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_authentication_hostnames_unique ON authentication_hostnames(project_uuid, hostname, session_name)",
		"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_hostname ON authentication_hostnames(project_uuid, hostname)",
		"CREATE INDEX IF NOT EXISTS idx_authentication_hostnames_project_scan ON authentication_hostnames(project_uuid, scan_uuid)",

		// -- scan_logs --
		"CREATE INDEX IF NOT EXISTS idx_scan_logs_project_scan ON scan_logs(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at)",

		// -- projects --
		"CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_uuid)",
	}

	// Drop old indexes before creating the correct ones (migration for existing databases).
	// Must run before CREATE UNIQUE INDEX so the unconditional unique index survives.
	// idx_findings_hash_unique was a global UNIQUE(finding_hash) — superseded by the
	// project-scoped idx_findings_project_hash_unique below. Dropping it lets the same
	// finding_hash coexist across projects.
	_, _ = db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_findings_hash")
	_, _ = db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_findings_hash_unique")

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
		_, _ = db.ExecContext(ctx, "DROP INDEX IF EXISTS "+idx)
	}

	for _, ddl := range indexes {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// Migrations for existing databases
	db.addColumnIfNotExists(ctx, "findings", "request", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "response", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "request_authorization", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "response_title", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "response_words", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "http_records", "source", "TEXT DEFAULT ''")
	db.addColumnIfNotExists(ctx, "http_records", "remarks", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "risk_score", "INTEGER DEFAULT 0")

	// Finding schema migrations
	db.addColumnIfNotExists(ctx, "findings", "confidence", "TEXT NOT NULL DEFAULT 'firm'")
	db.addColumnIfNotExists(ctx, "findings", "scan_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "module_type", "TEXT DEFAULT ''")
	db.addColumnIfNotExists(ctx, "findings", "finding_source", "TEXT DEFAULT ''")
	db.addColumnIfNotExists(ctx, "findings", "module_short", "TEXT DEFAULT ''")

	// Scan cursor tracking migrations
	db.addColumnIfNotExists(ctx, "scans", "scan_source", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "scan_mode", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "start_cursor_at", "TIMESTAMP")
	db.addColumnIfNotExists(ctx, "scans", "start_cursor_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "cursor_at", "TIMESTAMP")
	db.addColumnIfNotExists(ctx, "scans", "cursor_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "processed_count", "INTEGER DEFAULT 0")

	// Agent runs schema migrations
	db.addColumnIfNotExists(ctx, "agentic_scans", "session_id", "TEXT")

	// -- New field migrations (v2) --

	// Projects
	db.addColumnIfNotExists(ctx, "projects", "tags", "TEXT")
	db.addColumnIfNotExists(ctx, "projects", "default_target", "TEXT")
	db.addColumnIfNotExists(ctx, "projects", "last_scan_at", "TIMESTAMP")

	// Scans
	db.addColumnIfNotExists(ctx, "scans", "profile", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "source_path", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "tags", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "triggered_by", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "agentic_scan_uuid", "TEXT")

	// HTTP Records
	db.addColumnIfNotExists(ctx, "http_records", "scan_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "technology", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "content_hash", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "is_authenticated", "INTEGER NOT NULL DEFAULT 0")
	db.addColumnIfNotExists(ctx, "http_records", "parent_uuid", "TEXT")

	// Findings
	db.addColumnIfNotExists(ctx, "findings", "agentic_scan_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "url", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "hostname", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "status", "TEXT DEFAULT 'triaged'")
	db.addColumnIfNotExists(ctx, "findings", "remediation", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "cwe_id", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "cvss_score", "REAL DEFAULT 0")
	db.addColumnIfNotExists(ctx, "findings", "source_file", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "repo_name", "TEXT")

	// Agent Runs
	db.addColumnIfNotExists(ctx, "agentic_scans", "source_path", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "token_usage", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "retry_count", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "agentic_scans", "parent_run_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "input_record_count", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "agentic_scans", "session_dir", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "protocol", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "model", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "total_input_tokens", "INTEGER NOT NULL DEFAULT 0")
	db.addColumnIfNotExists(ctx, "agentic_scans", "total_output_tokens", "INTEGER NOT NULL DEFAULT 0")
	db.addColumnIfNotExists(ctx, "agentic_scans", "estimated_cost_usd", "REAL NOT NULL DEFAULT 0")

	db.addColumnIfNotExists(ctx, "scans", "storage_url", "TEXT")
	db.addColumnIfNotExists(ctx, "agentic_scans", "storage_url", "TEXT")

	// OAST Interactions
	db.addColumnIfNotExists(ctx, "oast_interactions", "finding_id", "INTEGER")
	db.addColumnIfNotExists(ctx, "oast_interactions", "payload", "TEXT")

	// Scopes
	db.addColumnIfNotExists(ctx, "scopes", "content_type_pattern", "TEXT")
	db.addColumnIfNotExists(ctx, "scopes", "hit_count", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "scopes", "last_matched_at", "TIMESTAMP")

	// Session Hostnames
	db.addColumnIfNotExists(ctx, "authentication_hostnames", "session_token", "TEXT")
	db.addColumnIfNotExists(ctx, "authentication_hostnames", "hydrated_at", "TIMESTAMP")

	// Project UUID migration for existing databases (backfill with default project)
	projectTables := []string{"scans", "http_records", "findings", "scopes", "oast_interactions", "scan_logs"}
	for _, table := range projectTables {
		db.addColumnIfNotExists(ctx, table, "project_uuid", fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", DefaultProjectUUID))
	}

	// Backfill empty project_uuid values — Bun ORM inserts explicit empty strings
	// which bypass the column DEFAULT, so rows created before ProjectUUID was
	// propagated through all code paths end up with project_uuid = ''.
	for _, table := range projectTables {
		_, _ = db.ExecContext(ctx,
			fmt.Sprintf("UPDATE %s SET project_uuid = ? WHERE project_uuid = ''", table),
			DefaultProjectUUID)
	}

	// Migrate legacy finding statuses: 'open' and 'confirmed' both collapse to
	// 'triaged' in the current state model (see models.Status* constants).
	_, _ = db.ExecContext(ctx, "UPDATE findings SET status = ? WHERE status IN (?, ?)",
		StatusTriaged, "open", "confirmed")

	// Backfill finding_records from existing JSONB data (idempotent)
	if db.driver == "postgres" {
		_, _ = db.ExecContext(ctx, `
			INSERT INTO finding_records (finding_id, record_uuid)
			SELECT f.id, je
			FROM findings f, jsonb_array_elements_text(f.http_record_uuids::jsonb) AS je
			WHERE f.http_record_uuids IS NOT NULL AND f.http_record_uuids != '' AND f.http_record_uuids != '[]'
			ON CONFLICT DO NOTHING
		`)
	} else {
		_, _ = db.ExecContext(ctx, `
			INSERT OR IGNORE INTO finding_records (finding_id, record_uuid)
			SELECT f.id, je.value
			FROM findings f, json_each(f.http_record_uuids) AS je
		`)
	}

	return nil
}

// SeedDefaults creates the default user and project if they don't exist.
// This is called during initialization to ensure CLI has a working project context.
func (db *DB) SeedDefaults(ctx context.Context) error {
	if db.driver == "postgres" {
		_, _ = db.ExecContext(ctx,
			"INSERT INTO users (uuid, name, email, created_at, updated_at) VALUES (?, ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (uuid) DO NOTHING",
			DefaultUserUUID, "vigolium-admin")
		_, _ = db.ExecContext(ctx,
			"INSERT INTO projects (uuid, name, description, owner_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (uuid) DO NOTHING",
			DefaultProjectUUID, "Default Project", "Auto-created default project", DefaultUserUUID)
	} else {
		_, _ = db.ExecContext(ctx,
			"INSERT OR IGNORE INTO users (uuid, name, email, created_at, updated_at) VALUES (?, ?, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
			DefaultUserUUID, "vigolium-admin")
		_, _ = db.ExecContext(ctx,
			"INSERT OR IGNORE INTO projects (uuid, name, description, owner_uuid, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
			DefaultProjectUUID, "Default Project", "Auto-created default project", DefaultUserUUID)
	}

	// Create FTS5 index for full-text search on HTTP records (SQLite only).
	// This replaces the CAST(blob AS TEXT) LIKE pattern which forces full table scans.
	if db.driver != "postgres" {
		_, ftsErr := db.ExecContext(ctx, `
			CREATE VIRTUAL TABLE IF NOT EXISTS http_records_fts USING fts5(
				url,
				path,
				hostname,
				raw_request,
				raw_response,
				content=http_records,
				content_rowid=rowid,
				tokenize='porter unicode61'
			)`)
		if ftsErr != nil {
			zap.L().Debug("FTS5 not available, falling back to CAST/LIKE searches", zap.Error(ftsErr))
		} else {
			db.hasFTS = true
			ftsTrigs := []string{
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ai AFTER INSERT ON http_records BEGIN
					INSERT INTO http_records_fts(rowid, url, path, hostname,
						raw_request, raw_response)
					VALUES (new.rowid, new.url, new.path, new.hostname,
						CAST(new.raw_request AS TEXT), CAST(new.raw_response AS TEXT));
				END`,
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ad AFTER DELETE ON http_records BEGIN
					INSERT INTO http_records_fts(http_records_fts, rowid, url, path, hostname,
						raw_request, raw_response)
					VALUES ('delete', old.rowid, old.url, old.path, old.hostname,
						CAST(old.raw_request AS TEXT), CAST(old.raw_response AS TEXT));
				END`,
			}
			for _, trig := range ftsTrigs {
				if _, err := db.ExecContext(ctx, trig); err != nil {
					zap.L().Debug("Failed to create FTS trigger", zap.Error(err))
				}
			}
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
			_, _ = db.ExecContext(ctx,
				"CREATE INDEX IF NOT EXISTS idx_http_records_search ON http_records USING GIN (search_vector)")
			db.hasFTS = true
		}
	}

	return nil
}

// addColumnIfNotExists attempts to add a column, ignoring errors if it already exists.
func (db *DB) addColumnIfNotExists(ctx context.Context, table, column, definition string) {
	ddl := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		// Ignore "duplicate column" errors (SQLite: "duplicate column name", Postgres: "already exists")
		errMsg := err.Error()
		if !strings.Contains(errMsg, "duplicate column") && !strings.Contains(errMsg, "already exists") {
			zap.L().Warn("Failed to add column", zap.String("column", column), zap.Error(err))
		}
	}
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
