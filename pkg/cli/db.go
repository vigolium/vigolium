package cli

import (
	"errors"
	"strings"

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
}

// The db subcommands' shared flags, registered only on the subcommands that
// read them (registerDBSharedFlags). They used to be persistent on `db`, so
// `db compact --search x` was accepted and did nothing.
const (
	dbFlagTable  = "table"
	dbFlagSearch = "search"
	dbFlagWatch  = "watch"
)

// registerDBSharedFlags adds the named shared db flags to cmd.
func registerDBSharedFlags(cmd *cobra.Command, names ...string) {
	f := cmd.Flags()
	for _, name := range names {
		switch name {
		case dbFlagTable:
			f.StringVar(&globalTable, dbFlagTable, "", "Database table to operate on (http_records, findings, scans)")
		case dbFlagSearch:
			f.StringVar(&dbSearch, dbFlagSearch, "", "Quick search across record fields (URLs, paths, descriptions)")
		case dbFlagWatch:
			f.StringVar(&globalWatchRaw, dbFlagWatch, "", "Re-run on interval (e.g. 10s, 1m, 5m)")
		default:
			panic("registerDBSharedFlags: unknown flag " + name)
		}
	}
}

// getDB returns the shared database connection, opening it on first use from
// the --config and --db global flags. The connection is cached in clicommon.
func getDB() (*database.DB, error) {
	return clicommon.GetDB(globalConfig, globalDB)
}

// closeDatabaseOnExit closes the shared database connection on command exit, and
// removes the scratch file a --glob-db merge or stateless JSONL load was built in
// (see newScratchDB). Order matters: the file cannot be removed until the handle
// on it is closed.
func closeDatabaseOnExit() {
	clicommon.CloseDatabaseOnExit()
	removeScratchDB()
}

// runWithWatch runs fn once, then repeats it every --watch interval if set.
//
// Under -j a repeated read is framed as NDJSON — one compact document per
// iteration, no clear-screen, no heading — rather than as a single document,
// because it is not one. Without this, `--json --watch 5` wrote an indented
// object, then ANSI clear codes and a "Refreshed at ..." line, then another
// object, forever: not parseable by anything.
func runWithWatch(fn func() error) error {
	opts := clicommon.WatchOptions{Raw: globalWatchRaw, JSON: globalJSON}
	if interval, err := clicommon.ParseWatchInterval(globalWatchRaw); err == nil && interval > 0 && globalJSON {
		jsonStreamMode = true
		// jsonStreamFramed outlives the loop on purpose: emitJSONError runs after
		// this function returns, and it needs to know stdout is a line stream that
		// one more line cannot corrupt. See its declaration in agentview.go.
		jsonStreamFramed = true
		defer func() { jsonStreamMode = false }()
	}
	err := clicommon.RunWithWatchOptions(opts, fn)
	// An unparseable interval and a mode that cannot repeat are both bad command
	// lines, not failed work: exit 2, so a caller can tell "you typed it wrong"
	// from "the read broke".
	if err != nil && isWatchUsageError(err) {
		return asUsageError(err)
	}
	return err
}

// isWatchUsageError reports whether err came from --watch validation rather than
// from the command body.
func isWatchUsageError(err error) bool {
	return errors.Is(err, clicommon.ErrWatchNotSupported) ||
		errors.Is(err, clicommon.ErrWatchInterval)
}

// resolvedReadDBPath names the database the current command actually opened, for
// the -j envelope's db_path. Under --glob-db it names the pattern instead of the
// scratch file: a temp path the caller cannot reopen is worse than useless as an
// assertion target, while the pattern is what the caller asked for.
// globDBNamesImportSources is set by `vigolium import`, whose --glob-db names
// the files to import rather than the database read: its db_path is the
// destination it wrote into.
var globDBNamesImportSources bool

func resolvedReadDBPath() string {
	if pattern := strings.TrimSpace(globalGlobDB); pattern != "" && !globDBNamesImportSources {
		return pattern
	}
	return clicommon.OpenedDBPath()
}
