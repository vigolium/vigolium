package storage

import (
	"github.com/uptrace/bun"
)

// DriverType represents the database driver type
type DriverType string

const (
	// DriverSQLite uses SQLite database
	DriverSQLite DriverType = "sqlite"
	// DriverPostgres uses PostgreSQL database
	DriverPostgres DriverType = "postgres"
)

// DatabaseDriver abstracts database-specific operations
type DatabaseDriver interface {
	// Open creates a bun database connection with the given DSN
	Open(dsn string) (*bun.DB, error)

	// ConfigurePool sets database-specific connection pool settings
	ConfigurePool(db *bun.DB, cfg *DatabaseConfig) error

	// BuildDSN constructs the driver-specific connection string
	BuildDSN(cfg *DatabaseConfig) string

	// GetDialectName returns "sqlite" or "postgres"
	GetDialectName() string

	// CleanupFiles removes database-specific temp files (WAL, SHM for SQLite)
	CleanupFiles(basePath string) error
}

// NewDriver creates a database driver based on type
func NewDriver(driverType DriverType) DatabaseDriver {
	switch driverType {
	case DriverPostgres:
		return &PostgresDriver{}
	default:
		return &SQLiteDriver{}
	}
}
