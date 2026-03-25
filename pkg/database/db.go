package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/driver/sqliteshim"
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

	// Build DSN with PRAGMA settings
	dsn := fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=%s&_synchronous=%s&_cache_size=%d",
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
			tags TEXT,
			triggered_by TEXT,
			agent_run_uuid TEXT,
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
			request_headers TEXT,
			request_content_type TEXT,
			request_content_length INTEGER DEFAULT 0,
			raw_request BLOB,
			request_body BLOB,
			request_hash TEXT NOT NULL,
			request_authorization TEXT,
			status_code INTEGER DEFAULT 0,
			status_phrase TEXT,
			response_http_version TEXT,
			response_headers TEXT,
			response_content_type TEXT,
			response_content_length INTEGER DEFAULT 0,
			raw_response BLOB,
			response_body BLOB,
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
			agent_run_uuid TEXT,
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
			status TEXT DEFAULT 'open',
			remediation TEXT,
			cwe_id TEXT,
			cvss_score REAL DEFAULT 0,
			source_file TEXT,
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
		`CREATE TABLE IF NOT EXISTS source_repos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_uuid TEXT NOT NULL,
			hostname TEXT NOT NULL,
			scan_uuid TEXT,
			name TEXT NOT NULL,
			root_path TEXT NOT NULL,
			repo_url TEXT,
			repo_type TEXT NOT NULL DEFAULT 'folder',
			language TEXT,
			framework TEXT,
			branch TEXT,
			commit_hash TEXT,
			endpoints TEXT,
			route_params TEXT,
			sinks TEXT,
			auth_endpoints TEXT,
			tags TEXT,
			metadata TEXT,
			line_count INTEGER DEFAULT 0,
			third_party_scan_status TEXT,
			third_party_scan_at TIMESTAMP,
			last_scanned_at TIMESTAMP,
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
		`CREATE TABLE IF NOT EXISTS agent_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			uuid TEXT NOT NULL UNIQUE,
			project_uuid TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
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
			session_id TEXT,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			duration_ms INTEGER DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS session_hostnames (
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
		"CREATE INDEX IF NOT EXISTS idx_records_request_hash ON http_records(request_hash)",
		"CREATE INDEX IF NOT EXISTS idx_records_response_hash ON http_records(response_hash)",

		// -- http_records: scan_uuid index --
		"CREATE INDEX IF NOT EXISTS idx_records_project_scan ON http_records(project_uuid, scan_uuid)",

		// -- findings: project-aware composite indexes --
		"CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings(project_uuid, severity)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_module ON findings(project_uuid, module_id)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_found_at ON findings(project_uuid, found_at)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_module_type ON findings(project_uuid, module_type)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_finding_source ON findings(project_uuid, finding_source)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_scan ON findings(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_findings_project_hostname ON findings(project_uuid, hostname)",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_hash_unique ON findings(finding_hash)",

		// -- finding_records --
		"CREATE INDEX IF NOT EXISTS idx_finding_records_record_uuid ON finding_records(record_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_finding_records_finding_id ON finding_records(finding_id)",

		// -- scans --
		"CREATE INDEX IF NOT EXISTS idx_scans_project_status ON scans(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_scans_project_created ON scans(project_uuid, created_at)",

		// -- scopes --
		"CREATE INDEX IF NOT EXISTS idx_scopes_project_enabled_priority ON scopes(project_uuid, enabled, priority)",

		// -- source_repos --
		"CREATE INDEX IF NOT EXISTS idx_source_repos_project_hostname ON source_repos(project_uuid, hostname)",

		// -- oast_interactions --
		"CREATE INDEX IF NOT EXISTS idx_oast_project_scan ON oast_interactions(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_oast_interactions_unique_id ON oast_interactions(unique_id)",

		// -- agent_runs --
		"CREATE INDEX IF NOT EXISTS idx_agent_runs_uuid ON agent_runs(uuid)",
		"CREATE INDEX IF NOT EXISTS idx_agent_runs_project_status ON agent_runs(project_uuid, status)",
		"CREATE INDEX IF NOT EXISTS idx_agent_runs_project_created ON agent_runs(project_uuid, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_agent_runs_scan ON agent_runs(scan_uuid)",

		// -- session_hostnames --
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_session_hostnames_unique ON session_hostnames(project_uuid, hostname, session_name)",
		"CREATE INDEX IF NOT EXISTS idx_session_hostnames_project_hostname ON session_hostnames(project_uuid, hostname)",
		"CREATE INDEX IF NOT EXISTS idx_session_hostnames_project_scan ON session_hostnames(project_uuid, scan_uuid)",

		// -- scan_logs --
		"CREATE INDEX IF NOT EXISTS idx_scan_logs_project_scan ON scan_logs(project_uuid, scan_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at)",

		// -- projects --
		"CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_uuid)",
	}

	// Drop old indexes before creating the correct ones (migration for existing databases)
	// Must run before CREATE UNIQUE INDEX so the unconditional unique index survives
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
		"idx_source_repos_hostname", "idx_source_repos_scan_uuid",
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

	// Source repo schema migrations
	db.addColumnIfNotExists(ctx, "source_repos", "repo_url", "TEXT")
	db.addColumnIfNotExists(ctx, "source_repos", "third_party_scan_status", "TEXT")
	db.addColumnIfNotExists(ctx, "source_repos", "third_party_scan_at", "TIMESTAMP")

	// Scan cursor tracking migrations
	db.addColumnIfNotExists(ctx, "scans", "scan_source", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "scan_mode", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "start_cursor_at", "TIMESTAMP")
	db.addColumnIfNotExists(ctx, "scans", "start_cursor_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "cursor_at", "TIMESTAMP")
	db.addColumnIfNotExists(ctx, "scans", "cursor_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "scans", "processed_count", "INTEGER DEFAULT 0")

	// Agent runs schema migrations
	db.addColumnIfNotExists(ctx, "agent_runs", "session_id", "TEXT")

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
	db.addColumnIfNotExists(ctx, "scans", "agent_run_uuid", "TEXT")

	// HTTP Records
	db.addColumnIfNotExists(ctx, "http_records", "scan_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "technology", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "content_hash", "TEXT")
	db.addColumnIfNotExists(ctx, "http_records", "is_authenticated", "INTEGER NOT NULL DEFAULT 0")
	db.addColumnIfNotExists(ctx, "http_records", "parent_uuid", "TEXT")

	// Findings
	db.addColumnIfNotExists(ctx, "findings", "agent_run_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "url", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "hostname", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "status", "TEXT DEFAULT 'open'")
	db.addColumnIfNotExists(ctx, "findings", "remediation", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "cwe_id", "TEXT")
	db.addColumnIfNotExists(ctx, "findings", "cvss_score", "REAL DEFAULT 0")
	db.addColumnIfNotExists(ctx, "findings", "source_file", "TEXT")

	// Source Repos
	db.addColumnIfNotExists(ctx, "source_repos", "branch", "TEXT")
	db.addColumnIfNotExists(ctx, "source_repos", "commit_hash", "TEXT")
	db.addColumnIfNotExists(ctx, "source_repos", "auth_endpoints", "TEXT")
	db.addColumnIfNotExists(ctx, "source_repos", "line_count", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "source_repos", "last_scanned_at", "TIMESTAMP")

	// Agent Runs
	db.addColumnIfNotExists(ctx, "agent_runs", "source_path", "TEXT")
	db.addColumnIfNotExists(ctx, "agent_runs", "token_usage", "TEXT")
	db.addColumnIfNotExists(ctx, "agent_runs", "retry_count", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "agent_runs", "parent_run_uuid", "TEXT")
	db.addColumnIfNotExists(ctx, "agent_runs", "input_record_count", "INTEGER DEFAULT 0")

	// OAST Interactions
	db.addColumnIfNotExists(ctx, "oast_interactions", "finding_id", "INTEGER")
	db.addColumnIfNotExists(ctx, "oast_interactions", "payload", "TEXT")

	// Scopes
	db.addColumnIfNotExists(ctx, "scopes", "content_type_pattern", "TEXT")
	db.addColumnIfNotExists(ctx, "scopes", "hit_count", "INTEGER DEFAULT 0")
	db.addColumnIfNotExists(ctx, "scopes", "last_matched_at", "TIMESTAMP")

	// Session Hostnames
	db.addColumnIfNotExists(ctx, "session_hostnames", "session_token", "TEXT")
	db.addColumnIfNotExists(ctx, "session_hostnames", "hydrated_at", "TIMESTAMP")

	// Project UUID migration for existing databases (backfill with default project)
	projectTables := []string{"scans", "http_records", "findings", "scopes", "source_repos", "oast_interactions", "scan_logs"}
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
				request_headers,
				response_headers,
				request_body,
				response_body,
				content=http_records,
				content_rowid=rowid,
				tokenize='porter unicode61'
			)`)
		if ftsErr != nil {
			zap.L().Debug("FTS5 not available, falling back to CAST/LIKE searches", zap.Error(ftsErr))
		} else {
			db.hasFTS = true
			// Triggers to keep FTS index in sync
			ftsTrigs := []string{
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ai AFTER INSERT ON http_records BEGIN
					INSERT INTO http_records_fts(rowid, url, path, hostname,
						request_headers, response_headers,
						request_body, response_body)
					VALUES (new.rowid, new.url, new.path, new.hostname,
						new.request_headers, new.response_headers,
						CAST(new.request_body AS TEXT), CAST(new.response_body AS TEXT));
				END`,
				`CREATE TRIGGER IF NOT EXISTS http_records_fts_ad AFTER DELETE ON http_records BEGIN
					INSERT INTO http_records_fts(http_records_fts, rowid, url, path, hostname,
						request_headers, response_headers,
						request_body, response_body)
					VALUES ('delete', old.rowid, old.url, old.path, old.hostname,
						old.request_headers, old.response_headers,
						CAST(old.request_body AS TEXT), CAST(old.response_body AS TEXT));
				END`,
			}
			for _, trig := range ftsTrigs {
				if _, err := db.ExecContext(ctx, trig); err != nil {
					zap.L().Debug("Failed to create FTS trigger", zap.Error(err))
				}
			}
		}
	} else {
		// PostgreSQL: use tsvector with GIN index for full-text search
		_, pgErr := db.ExecContext(ctx, `
			ALTER TABLE http_records
			ADD COLUMN IF NOT EXISTS search_vector tsvector
			GENERATED ALWAYS AS (
				to_tsvector('english',
					coalesce(url, '') || ' ' ||
					coalesce(path, '') || ' ' ||
					coalesce(hostname, '') || ' ' ||
					coalesce(request_headers, '') || ' ' ||
					coalesce(response_headers, '')
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
