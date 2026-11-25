package config

import (
	"fmt"
	"time"
)

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Driver   string         `yaml:"driver"` // sqlite or postgres
	SQLite   SQLiteConfig   `yaml:"sqlite"`
	Postgres PostgresConfig `yaml:"postgres"`

	// AutoMigrateOnRead lets any command, read or write, bring a store written
	// by an older vigolium up to date when it opens it. Off by default: an
	// outdated store is refused with schema_outdated and the remedy
	// `vigolium db migrate --db <path>`, so a migration (which can be O(rows)
	// and leaves the file unreadable by the older binary) never runs inside a
	// caller's deadline unasked. VIGOLIUM_AUTO_MIGRATE overrides it; read it
	// through MigratesImplicitly.
	AutoMigrateOnRead bool `yaml:"auto_migrate_on_read"`

	// ReadIntent opens a read pool rather than the read-write store: SQLite gets
	// query_only(1), deferred transactions, no journal-mode PRAGMA and no WAL
	// checkpointing; Postgres sessions default to read-only transactions. Set
	// per process by the CLI from the command's declared database intent, never
	// persisted to YAML.
	ReadIntent bool `yaml:"-"`
}

// SQLiteConfig holds SQLite-specific settings
type SQLiteConfig struct {
	Path         string `yaml:"path"`
	BusyTimeout  int    `yaml:"busy_timeout"`
	JournalMode  string `yaml:"journal_mode"`
	Synchronous  string `yaml:"synchronous"`
	CacheSize    int    `yaml:"cache_size"`
	MaxOpenConns int    `yaml:"max_open_conns"`

	// ReadOnly opens the file without touching it: no parent-directory creation,
	// no journal-mode PRAGMA, no startup WAL checkpoint, and the driver's own
	// read-only mode. It is not persisted to YAML — it is set by the read
	// commands for the duration of one process.
	//
	// Opening a database used to be a write whatever the command did with it:
	// `traffic -S --db evidence.sqlite -j` rewrote the file's header (flipping
	// journal_mode from delete to wal), changed its SHA-256, and dropped -shm /
	// -wal siblings next to it — while a chmod 444 file could not be read at all.
	// For a store that is evidence rather than working state, a read that alters
	// the artifact is the one thing it must never do.
	ReadOnly bool `yaml:"-"`
}

// PostgresConfig holds PostgreSQL-specific settings
type PostgresConfig struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	User            string `yaml:"user"`
	Password        string `yaml:"password"`
	Database        string `yaml:"database"`
	SSLMode         string `yaml:"sslmode"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`
}

// AutoMigrateEnvVar overrides database.auto_migrate_on_read: truthy values
// (1, true, yes, on) let an open migrate an outdated store, falsy values
// (0, false, no, off) refuse it. Unset means "use the YAML config".
const AutoMigrateEnvVar = "VIGOLIUM_AUTO_MIGRATE"

// MigratesImplicitly reports whether opening an outdated store may migrate
// it: VIGOLIUM_AUTO_MIGRATE when set to a recognised value, else
// auto_migrate_on_read.
func (c *DatabaseConfig) MigratesImplicitly() bool {
	if v, ok := envBoolOverride(AutoMigrateEnvVar); ok {
		return v
	}
	return c.AutoMigrateOnRead
}

// DefaultDatabaseConfig returns default configuration
func DefaultDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Enabled: true,
		Driver:  "sqlite",
		SQLite: SQLiteConfig{
			Path:         "~/.vigolium/database-vgnm.sqlite",
			BusyTimeout:  15000,
			JournalMode:  "WAL",
			Synchronous:  "NORMAL",
			CacheSize:    10000,
			MaxOpenConns: 8, // WAL: concurrent readers + 1 writer (see openSQLite)
		},
		Postgres: PostgresConfig{
			Host:            "localhost",
			Port:            5432,
			User:            "vigolium",
			Database:        "vigolium",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: "5m",
		},
	}
}

// Validate checks configuration validity
func (c *DatabaseConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Driver != "sqlite" && c.Driver != "postgres" {
		return fmt.Errorf("invalid database driver: %s (must be 'sqlite' or 'postgres')", c.Driver)
	}

	if c.Driver == "sqlite" {
		if c.SQLite.Path == "" {
			return fmt.Errorf("sqlite path cannot be empty")
		}
		if c.SQLite.BusyTimeout < 0 {
			return fmt.Errorf("sqlite busy_timeout must be >= 0")
		}
		validJournalModes := map[string]bool{
			"DELETE": true, "TRUNCATE": true, "PERSIST": true,
			"MEMORY": true, "WAL": true, "OFF": true,
		}
		if !validJournalModes[c.SQLite.JournalMode] {
			return fmt.Errorf("invalid sqlite journal_mode: %s", c.SQLite.JournalMode)
		}
		validSyncModes := map[string]bool{
			"OFF": true, "NORMAL": true, "FULL": true, "EXTRA": true,
		}
		if !validSyncModes[c.SQLite.Synchronous] {
			return fmt.Errorf("invalid sqlite synchronous mode: %s", c.SQLite.Synchronous)
		}
	}

	if c.Driver == "postgres" {
		if c.Postgres.Host == "" {
			return fmt.Errorf("postgres host cannot be empty")
		}
		if c.Postgres.Port <= 0 || c.Postgres.Port > 65535 {
			return fmt.Errorf("postgres port must be between 1 and 65535")
		}
		if c.Postgres.User == "" {
			return fmt.Errorf("postgres user cannot be empty")
		}
		if c.Postgres.Database == "" {
			return fmt.Errorf("postgres database cannot be empty")
		}
		if c.Postgres.MaxOpenConns < 1 {
			return fmt.Errorf("postgres max_open_conns must be >= 1")
		}
		if c.Postgres.MaxIdleConns < 0 {
			return fmt.Errorf("postgres max_idle_conns must be >= 0")
		}
		if c.Postgres.ConnMaxLifetime != "" {
			if _, err := time.ParseDuration(c.Postgres.ConnMaxLifetime); err != nil {
				return fmt.Errorf("invalid postgres conn_max_lifetime: %w", err)
			}
		}
	}

	return nil
}
