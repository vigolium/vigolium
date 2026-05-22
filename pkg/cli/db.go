package cli

import (
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage database records",
	Long:  "Inspect and manage scan data persisted in the local SQLite or PostgreSQL database. Subcommands list and query records, dump statistics, export findings or HTTP traffic, and prune stale entries.",
}

// globalTable is the --table flag shared across all db subcommands
var globalTable string

// dbSearch is the --search flag shared across all db subcommands
var dbSearch string

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.PersistentFlags().StringVar(&globalTable, "table", "", "Database table to operate on (http_records, findings, scans)")
	dbCmd.PersistentFlags().StringVar(&dbSearch, "search", "", "Quick search across record fields (URLs, paths, descriptions)")
	dbCmd.PersistentFlags().StringVar(&globalWatchRaw, "watch", "", "Re-run on interval (e.g. 10s, 1m, 5m)")
}

// getDB returns the shared database connection, opening it on first use from
// the --config and --db global flags. The connection is cached in clicommon.
func getDB() (*database.DB, error) {
	return clicommon.GetDB(globalConfig, globalDB)
}

// closeDatabaseOnExit closes the shared database connection on command exit.
func closeDatabaseOnExit() {
	clicommon.CloseDatabaseOnExit()
}

// runWithWatch runs fn once, then repeats it every --watch interval if set.
func runWithWatch(fn func() error) error {
	return clicommon.RunWithWatch(globalWatchRaw, fn)
}
