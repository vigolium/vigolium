// Package clicommon holds shared, leaf-level helpers used across the vigolium
// CLI command tree: the database-connection cache, project resolution, the
// --watch loop, logger flushing, and display formatting. It is intentionally
// dependency-light (no imports back into pkg/cli) so command groups can be
// split into their own subpackages and still share this common ground.
package clicommon

import (
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// dbConn is the process-wide cached database connection shared by every command.
var dbConn *database.DB

// GetDB returns the cached database connection, opening it on first use.
// configPath is the --config path (may be empty) and dbPath is the --db SQLite
// override (may be empty). When the database is not explicitly enabled it
// defaults to SQLite at the standard location.
func GetDB(configPath, dbPath string) (*database.DB, error) {
	if dbConn != nil {
		return dbConn, nil
	}

	settings, err := config.LoadSettings(configPath)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// If database is not explicitly enabled, default to SQLite
	if !settings.Database.Enabled && settings.Database.Driver == "" {
		settings.Database.Enabled = true
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = "~/.vigolium/database-vgnm.sqlite"
	}

	// Override SQLite path if --db flag is set
	if dbPath != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = dbPath
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	dbConn = db
	return db, nil
}

// CloseDatabaseOnExit closes the cached connection if open. Safe to defer.
func CloseDatabaseOnExit() {
	if dbConn != nil {
		_ = dbConn.Close()
	}
}

// ResetDBCache closes and clears the cached connection. Used by `db clean`
// before deleting the underlying SQLite file.
func ResetDBCache() {
	if dbConn != nil {
		_ = dbConn.Close()
		dbConn = nil
	}
}

// SetDBCache replaces the cached connection. Used by `db clean` after it
// recreates the database with a fresh schema.
func SetDBCache(db *database.DB) {
	dbConn = db
}
