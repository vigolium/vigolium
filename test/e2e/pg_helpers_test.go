//go:build e2e || canary

package e2e

import (
	"context"
	"fmt"
	"os"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

// pgTestConfigFromEnv returns a PostgreSQL database config derived from env
// vars, with defaults matching test/testdata/postgres/docker-compose.yaml.
func pgTestConfigFromEnv() *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Enabled: true,
		Driver:  "postgres",
		Postgres: config.PostgresConfig{
			Host:            envOr("VIGOLIUM_PG_HOST", "localhost"),
			Port:            envOrInt("VIGOLIUM_PG_PORT", 5433),
			User:            envOr("VIGOLIUM_PG_USER", "vigolium_test"),
			Password:        envOr("VIGOLIUM_PG_PASSWORD", "vigolium_test_pass"),
			Database:        envOr("VIGOLIUM_PG_DATABASE", "vigolium_test"),
			SSLMode:         "disable",
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: "5m",
		},
	}
}

// allVigoliumTables is the full set of tables created by db.CreateSchema.
// Kept in dependency-safe drop order (children before parents) although
// DROP ... CASCADE makes order non-critical.
var allVigoliumTables = []string{
	"scan_logs",
	"oast_interactions",
	"authentication_hostnames",
	"agentic_scans",
	"scopes",
	"finding_records",
	"findings",
	"http_records",
	"scans",
	"projects",
	"users",
}

// dropAllVigoliumTables issues DROP TABLE IF EXISTS ... CASCADE for every
// table defined by the current schema. Call this before CreateSchema to give
// each test a clean slate on a shared PostgreSQL instance.
func dropAllVigoliumTables(ctx context.Context, db *database.DB) {
	for _, tbl := range allVigoliumTables {
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", tbl))
	}
}
