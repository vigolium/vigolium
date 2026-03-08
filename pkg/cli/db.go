package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage database records",
}

// Shared database connection for all subcommands
var dbConnection *database.DB

// globalTable is the --table flag shared across all db subcommands
var globalTable string

// dbSearch is the --search flag shared across all db subcommands
var dbSearch string

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.PersistentFlags().StringVar(&globalTable, "table", "", "Database table to operate on (http_records, findings, scans)")
	dbCmd.PersistentFlags().StringVar(&dbSearch, "search", "", "Quick search across record fields (URLs, paths, descriptions)")
}

// getDB returns a database connection (lazy initialization)
func getDB() (*database.DB, error) {
	if dbConnection != nil {
		return dbConnection, nil
	}

	settings, err := config.LoadSettings(globalConfig)
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
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	dbConnection = db
	return db, nil
}

// closeDatabaseOnExit ensures database is closed when command exits
func closeDatabaseOnExit() {
	if dbConnection != nil {
		_ = dbConnection.Close()
	}
}

// parseWatchInterval parses the --watch value. Bare integers (e.g. "5") are
// treated as seconds; otherwise standard Go duration syntax is used (5s, 1m, 1h).
func parseWatchInterval() (time.Duration, error) {
	raw := globalWatchRaw
	if raw == "" {
		return 0, nil
	}
	// Bare integer → treat as seconds
	if n, err := strconv.Atoi(raw); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(raw)
}

// runWithWatch runs fn once, then repeats it every --watch interval if set.
// It clears the screen between iterations and exits on Ctrl+C.
func runWithWatch(fn func() error) error {
	if err := fn(); err != nil {
		return err
	}

	interval, err := parseWatchInterval()
	if err != nil {
		return fmt.Errorf("invalid --watch value %q: %w", globalWatchRaw, err)
	}
	if interval <= 0 {
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	for {
		select {
		case <-sigChan:
			return nil
		case <-time.After(interval):
			// Clear screen and move cursor to top-left
			fmt.Print("\033[2J\033[H")
			fmt.Printf("%s Refreshed at %s (every %s, Ctrl+C to stop)\n\n",
				terminal.InfoSymbol(),
				terminal.Gray(time.Now().Format("15:04:05")),
				terminal.Cyan(interval.String()))
			if err := fn(); err != nil {
				return err
			}
		}
	}
}
