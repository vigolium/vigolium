package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// PostgresDriver implements DatabaseDriver for PostgreSQL
type PostgresDriver struct{}

// Open creates a bun database connection for PostgreSQL
func (d *PostgresDriver) Open(dsn string) (*bun.DB, error) {
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	return bun.NewDB(sqldb, pgdialect.New()), nil
}

// ConfigurePool sets PostgreSQL-specific connection pool settings
func (d *PostgresDriver) ConfigurePool(db *bun.DB, cfg *DatabaseConfig) error {
	sqlDB := db.DB

	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = DefaultMaxOpenConns
	}

	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = DefaultMaxIdleConns
	}

	connMaxLife := cfg.ConnMaxLifetime
	if connMaxLife <= 0 {
		connMaxLife = DefaultConnMaxLifetime
	}

	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetConnMaxLifetime(connMaxLife)

	return nil
}

// BuildDSN constructs PostgreSQL connection string
func (d *PostgresDriver) BuildDSN(cfg *DatabaseConfig) string {
	port := cfg.Port
	if port <= 0 {
		port = 5432
	}

	sslMode := cfg.SSLMode
	if sslMode == "" {
		sslMode = "prefer"
	}

	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, port, cfg.Database, sslMode,
	)
}

// GetDialectName returns "postgres"
func (d *PostgresDriver) GetDialectName() string {
	return "postgres"
}

// CleanupFiles is a no-op for PostgreSQL (no local files)
func (d *PostgresDriver) CleanupFiles(basePath string) error {
	return nil
}

// Ensure compile-time interface compliance
var _ DatabaseDriver = (*PostgresDriver)(nil)
var _ DatabaseDriver = (*SQLiteDriver)(nil)

// Default connection pool settings for PostgreSQL
// Optimized for 100+ concurrent deparos instances with PgBouncer
// Deparos serializes writes via mutex, so few connections are needed
const (
	DefaultMaxOpenConns    = 5                // Deparos serializes writes, doesn't need many
	DefaultMaxIdleConns    = 2                // Reduce idle resource usage
	DefaultConnMaxLifetime = 10 * time.Minute // Reduce reconnection overhead
)
