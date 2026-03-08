package storage

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultMaxBodySize is the default maximum body size to store (50MB)
	DefaultMaxBodySize = 50 * 1024 * 1024
	// DefaultBusyTimeout is the default SQLite busy timeout in milliseconds.
	// Set to 60 seconds to handle multi-process concurrent access scenarios
	// where many processes compete for the same SQLite file.
	DefaultBusyTimeout = 60000
)

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	// Driver type: "sqlite" or "postgres"
	Driver DriverType

	// SQLite-specific
	FilePath    string
	BusyTimeout int

	// PostgreSQL-specific
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string

	// Connection pool (primarily for PostgreSQL)
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// StorageConfig configures the sitemap storage backend
type StorageConfig struct {
	// Database configuration
	Database DatabaseConfig

	// TargetURL is the primary target URL for this scan
	TargetURL string

	// SessionName is custom session identifier (empty = auto-generate UUID)
	SessionName string

	// MaxBodySize truncates bodies larger than this (default: 50MB)
	// Set to 0 to store full bodies (not recommended for large scans)
	MaxBodySize int64

	// SaveResponseBody enables storing HTTP response bodies in the database.
	// Disabled by default to save disk space.
	SaveResponseBody bool
}

// DefaultConfig returns a default configuration for ephemeral SQLite storage
func DefaultConfig() *StorageConfig {
	return &StorageConfig{
		Database: DatabaseConfig{
			Driver:      DriverSQLite,
			FilePath:    "", // Empty = ephemeral (temp file)
			BusyTimeout: DefaultBusyTimeout,
		},
		MaxBodySize: DefaultMaxBodySize,
	}
}

// SQLiteConfig returns a configuration for persistent SQLite storage
func SQLiteConfig(filePath string) *StorageConfig {
	return &StorageConfig{
		Database: DatabaseConfig{
			Driver:      DriverSQLite,
			FilePath:    filePath,
			BusyTimeout: DefaultBusyTimeout,
		},
		MaxBodySize: DefaultMaxBodySize,
	}
}

// PostgresConfig returns a configuration for PostgreSQL storage
func PostgresConfig(host, database, user, password string) *StorageConfig {
	return &StorageConfig{
		Database: DatabaseConfig{
			Driver:          DriverPostgres,
			Host:            host,
			Port:            5432,
			User:            user,
			Password:        password,
			Database:        database,
			SSLMode:         "prefer",
			MaxOpenConns:    DefaultMaxOpenConns,
			MaxIdleConns:    DefaultMaxIdleConns,
			ConnMaxLifetime: DefaultConnMaxLifetime,
		},
		MaxBodySize: DefaultMaxBodySize,
	}
}

// IsEphemeral returns true if storage will use a temp file (SQLite only)
func (c *StorageConfig) IsEphemeral() bool {
	return c.Database.Driver == DriverSQLite && c.Database.FilePath == ""
}

// IsPostgres returns true if using PostgreSQL
func (c *StorageConfig) IsPostgres() bool {
	return c.Database.Driver == DriverPostgres
}

// ParseDSN parses a database connection string and returns appropriate StorageConfig.
//
// Supported formats:
//   - PostgreSQL URI: postgres://user:pass@host:port/dbname?sslmode=require
//   - SQLite path: /path/to/file.db or file.db
//   - Empty string: ephemeral SQLite (temp file)
//
// Environment variable expansion is NOT performed - callers should expand if needed.
func ParseDSN(dsn string) (*StorageConfig, error) {
	if dsn == "" {
		return DefaultConfig(), nil
	}

	// Check if it's a PostgreSQL URI
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return parsePostgresDSN(dsn)
	}

	// Otherwise treat as SQLite file path
	return SQLiteConfig(dsn), nil
}

// parsePostgresDSN parses a PostgreSQL connection URI.
// Format: postgres://user:password@host:port/database?sslmode=value
func parsePostgresDSN(dsn string) (*StorageConfig, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid postgres URI: %w", err)
	}

	cfg := &StorageConfig{
		Database: DatabaseConfig{
			Driver:          DriverPostgres,
			Host:            u.Hostname(),
			Port:            5432, // default
			SSLMode:         "prefer",
			MaxOpenConns:    DefaultMaxOpenConns,
			MaxIdleConns:    DefaultMaxIdleConns,
			ConnMaxLifetime: DefaultConnMaxLifetime,
		},
		MaxBodySize: DefaultMaxBodySize,
	}

	// Parse port
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		cfg.Database.Port = port
	}

	// Parse user/password
	if u.User != nil {
		cfg.Database.User = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			cfg.Database.Password = pass
		}
	}

	// Parse database name (path without leading /)
	cfg.Database.Database = strings.TrimPrefix(u.Path, "/")

	// Parse query parameters
	q := u.Query()
	if sslmode := q.Get("sslmode"); sslmode != "" {
		cfg.Database.SSLMode = sslmode
	}

	// Validate required fields
	if cfg.Database.Host == "" {
		return nil, fmt.Errorf("postgres URI missing host")
	}
	if cfg.Database.Database == "" {
		return nil, fmt.Errorf("postgres URI missing database name")
	}

	return cfg, nil
}
