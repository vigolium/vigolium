package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// SQLiteDriver implements DatabaseDriver for SQLite
type SQLiteDriver struct{}

// Open creates a bun database connection for SQLite
func (d *SQLiteDriver) Open(dsn string) (*bun.DB, error) {
	sqldb, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}
	return bun.NewDB(sqldb, sqlitedialect.New()), nil
}

// ConfigurePool sets SQLite-specific connection settings for multi-process concurrent access.
// Core PRAGMAs are set explicitly here since sqliteshim may not honor DSN parameters
// like _journal_mode, _busy_timeout, and _synchronous.
func (d *SQLiteDriver) ConfigurePool(db *bun.DB, cfg *DatabaseConfig) error {
	sqlDB := db.DB

	// Connection pool per process - keep low since multiple processes share the same DB file
	// Example: 20 processes x 5 conns = 100 total connections competing for locks
	sqlDB.SetMaxOpenConns(5)
	sqlDB.SetMaxIdleConns(2)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	ctx := context.Background()

	// Set busy_timeout FIRST so subsequent PRAGMAs can wait for locks
	timeout := max(cfg.BusyTimeout, 60000)
	if _, err := db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", timeout)); err != nil {
		return fmt.Errorf("failed to set busy_timeout: %w", err)
	}

	// Set WAL mode — persistent setting, may fail if DB is locked by another process
	// but will succeed on verification if previously set
	_, _ = db.ExecContext(ctx, "PRAGMA journal_mode=WAL")

	// Verify WAL mode is active
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("failed to get journal_mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("WAL mode not enabled, got: %s", journalMode)
	}

	if _, err := db.ExecContext(ctx, "PRAGMA synchronous=NORMAL"); err != nil {
		return fmt.Errorf("failed to set synchronous: %w", err)
	}

	// Additional performance PRAGMAs
	_, _ = db.ExecContext(ctx, "PRAGMA cache_size=-64000")
	_, _ = db.ExecContext(ctx, "PRAGMA temp_store=MEMORY")
	_, _ = db.ExecContext(ctx, "PRAGMA mmap_size=268435456")
	_, _ = db.ExecContext(ctx, "PRAGMA wal_autocheckpoint=1000")

	// Crash recovery: Checkpoint WAL on open to recover from previous crashes
	_, _ = db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")

	return nil
}

// BuildDSN constructs SQLite connection string with optimal settings for concurrent access.
// mattn/go-sqlite3 uses "file:" URI format with query parameters.
//
// Key settings for multi-process concurrent access:
// - _txlock=immediate: Acquire write lock immediately to prevent deadlocks
// - _journal_mode=WAL: Allow concurrent readers with a single writer
// - _busy_timeout: Wait up to 60s for locks
// - _synchronous=NORMAL: Balanced durability/performance (safer than OFF)
func (d *SQLiteDriver) BuildDSN(cfg *DatabaseConfig) string {
	timeout := max(cfg.BusyTimeout, 60000) // Minimum 60 seconds for multi-process

	return fmt.Sprintf("file:%s?_txlock=immediate&_busy_timeout=%d&_journal_mode=WAL&_synchronous=NORMAL",
		cfg.FilePath, timeout)
}

// GetDialectName returns "sqlite"
func (d *SQLiteDriver) GetDialectName() string {
	return "sqlite"
}

// CleanupFiles
func (d *SQLiteDriver) CleanupFiles(basePath string) error {
	return nil
}
