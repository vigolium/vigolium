package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var dbCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean database records",
	Long: "Delete records from the database by host, scan UUID, age, status, or severity. " +
		"Supports --dry-run to preview and --orphans to remove orphaned findings; disk space is reclaimed " +
		"automatically with VACUUM after a delete. Use --all --force to delete every row from the data tables, " +
		"or `vigolium db reset --force` to delete and recreate the database file from scratch. " +
		"A bare `db clean` with no selector is rejected — it never wipes the database implicitly.",
	Args: cobra.NoArgs,
	RunE: runDBClean,
}

var dbResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Delete and recreate the database from scratch (SQLite only)",
	Long: "Remove the SQLite database file (and its WAL/SHM companions) and recreate it with a fresh, empty " +
		"schema. This is destructive and irreversible: all scans, HTTP records, and findings are lost. " +
		"Requires --force, or confirm interactively when run on a TTY.",
	Args: cobra.NoArgs,
	RunE: runDBReset,
}

var (
	cleanAll      bool
	cleanHost     string
	cleanScanUUID string
	cleanBefore   string
	cleanStatus   []int
	cleanSeverity string
	cleanDryRun   bool
	cleanOrphans  bool
	cleanFindings bool
	cleanTable    string
)

func init() {
	dbCmd.AddCommand(dbCleanCmd)
	dbCmd.AddCommand(dbResetCmd)

	dbCleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Delete every row from all data tables (requires --force unless --dry-run)")
	dbCleanCmd.Flags().StringVar(&cleanHost, "host", "", "Delete records on this host: hostname, host:port, origin (https://host[:port]) or bracketed IPv6; * wildcards")
	dbCleanCmd.Flags().StringVar(&cleanScanUUID, "scan-uuid", "", "Delete records belonging to the specified scan UUID")
	dbCleanCmd.Flags().StringVar(&cleanBefore, "before", "", fmt.Sprintf("Delete records created strictly before this time — %s (the named day itself is kept)", clicommon.TimeFilterSyntax))
	dbCleanCmd.Flags().IntSliceVar(&cleanStatus, "status", nil, "Delete records with matching HTTP status codes")
	dbCleanCmd.Flags().StringVar(&cleanSeverity, "severity", "", "Delete findings matching the specified severity level (findings only; HTTP records are kept)")

	dbCleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "Show what would be deleted without deleting")

	dbCleanCmd.Flags().BoolVar(&cleanOrphans, "orphans", false, "Delete findings with no matching HTTP record")

	dbCleanCmd.Flags().BoolVar(&cleanFindings, "findings-only", false, "Delete findings only, keep HTTP records")
	dbCleanCmd.Flags().StringVar(&cleanTable, "table", "", "Delete all rows from a specific table (e.g., http_records, findings, scans)")
}

func runDBReset(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	if !globalForce {
		fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(),
			terminal.Yellow("This will DELETE and recreate the entire database. All scans, HTTP records, and findings will be lost."))
	}
	if done, err := handleConfirmation("deleting and recreating the entire database"); done {
		if err == nil && globalJSON {
			return emitMutation(cmd, "", mutationResult{Action: "noop", Extra: map[string]any{"aborted": true}})
		}
		return err
	}
	res, err := resetDatabase()
	if err != nil {
		return err
	}
	if globalJSON {
		// Always a change: even with no file to delete, a fresh database now
		// exists where there was none.
		return emitMutation(cmd, "", mutationResult{
			Changed: true,
			Action:  "reset",
			Items:   []dbResetView{res},
		}, withDBPath(res.Path))
	}
	return nil
}

// dbResetView is the `db reset -j` row: the file recreated, and how many of
// the database file and its WAL/SHM companions existed and were removed.
type dbResetView struct {
	Path         string `json:"path"`
	FilesRemoved int    `json:"files_removed"`
}

// dbCleanView is one table's row in `db clean -j`: rows the selection matched
// there. Under --dry-run nothing was deleted; otherwise every matched row was.
type dbCleanView struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
}

// cleanModeTableName names the table a scoped clean mode deletes from.
func cleanModeTableName(sel *cleanSelection) string {
	switch sel.Mode {
	case cleanModeFindings, cleanModeOrphans:
		return "findings"
	case cleanModeTable:
		return sel.Table
	default:
		return "http_records"
	}
}

// cleanCountsView orders per-table counts for output: the mode's own table
// first (always present, even at 0), then every other table the delete
// touched in dependency order.
func cleanCountsView(sel *cleanSelection, counts database.DeleteCounts) []dbCleanView {
	primary := cleanModeTableName(sel)
	items := []dbCleanView{{Table: primary, Rows: counts[primary]}}
	seen := map[string]bool{primary: true}
	for _, tbl := range database.AllTablesDeleteOrder() {
		if seen[tbl] || counts[tbl] == 0 {
			continue
		}
		seen[tbl] = true
		items = append(items, dbCleanView{Table: tbl, Rows: counts[tbl]})
	}
	var rest []string
	for tbl, n := range counts {
		if !seen[tbl] && n > 0 {
			rest = append(rest, tbl)
		}
	}
	sort.Strings(rest)
	for _, tbl := range rest {
		items = append(items, dbCleanView{Table: tbl, Rows: counts[tbl]})
	}
	return items
}

// emitDBClean writes the `db clean -j` document. deleted is the total actually
// removed (0 for a dry run or an empty selection); items are the per-table
// matched counts.
func emitDBClean(cmd *cobra.Command, sel *cleanSelection, items []dbCleanView, matched, deleted int64, aborted bool) error {
	action := "delete"
	if deleted == 0 && !cleanDryRun {
		action = "noop"
	}
	extra := map[string]any{
		"mode":         string(sel.Mode),
		"scope":        sel.describeScope(),
		"store_wide":   sel.StoreWide,
		"rows_matched": matched,
		"rows_deleted": deleted,
	}
	if aborted {
		extra["aborted"] = true
	}
	var opts []envOpt
	if !sel.StoreWide {
		opts = append(opts, withProjectScope(sel.Filters.ProjectUUID))
	}
	opts = append(opts, withDBPath(resolvedReadDBPath()))
	return emitMutation(cmd, "", mutationResult{
		Changed: deleted > 0,
		Action:  action,
		DryRun:  cleanDryRun,
		Items:   items,
		Extra:   extra,
	}, opts...)
}
func runDBClean(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// A bare `db clean` with no selector must never implicitly wipe the database.
	// --all --force deletes every row; `db reset --force` recreates the DB file.
	noSelector := !cleanAll && cleanHost == "" && cleanScanUUID == "" && cleanBefore == "" &&
		len(cleanStatus) == 0 && cleanSeverity == "" && !cleanOrphans && !cleanFindings &&
		cleanTable == "" && dbSearch == ""
	if noSelector {
		return usageErrorf("no clean selector provided; narrow the delete with a filter " +
			"(--host, --scan-uuid, --before, --status, --severity, --search, --orphans, --findings-only, --table), " +
			"use `--all --force` to delete all records, " +
			"or use `vigolium db reset --force` to delete and recreate the database")
	}

	// Project resolution and combination validation both happen before getDB, so
	// a rejected command line never opens a writable connection. The old order
	// branched into a delete handler first and validated inside it, which is how
	// --findings-only reached a store-wide DELETE with a --host on the command
	// line that nothing ever read.
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}
	sel, err := resolveCleanSelection(projectUUID)
	if err != nil {
		return err
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx := context.Background()
	if sel.Mode == cleanModeAll {
		return cleanAllTables(ctx, cmd, db, sel)
	}
	return runScopedClean(ctx, cmd, db, sel)
}

// applySelection performs the selection, or runs it and rolls it back when
// dryRun is set, and returns the rows per table. Count and delete go through
// ONE switch so a mode added later cannot be wired into the preview and
// forgotten in the delete — which is the class of divergence this whole file
// exists to prevent.
func applySelection(ctx context.Context, del *database.DeleteBuilder, sel *cleanSelection, dryRun bool) (database.DeleteCounts, error) {
	switch sel.Mode {
	case cleanModeOrphans:
		return del.DeleteOrphansByTable(ctx, dryRun)
	case cleanModeFindings:
		return del.DeleteFindingsByTable(ctx, dryRun)
	case cleanModeTable:
		return del.DeleteTableByTable(ctx, sel.Table, dryRun)
	default:
		return del.DeleteRecordsByTable(ctx, dryRun)
	}
}

// runScopedClean is the single count -> preview -> confirm -> delete path shared
// by every mode except --all, which reports per-table counts and has its own
// renderer.
func runScopedClean(ctx context.Context, cmd *cobra.Command, db *database.DB, sel *cleanSelection) error {
	del := database.NewDeleteBuilder(db, sel.Filters)

	// The preview runs the delete and rolls it back, so the per-table counts
	// it shows are exactly what the real run removes.
	preview, err := applySelection(ctx, del, sel, true)
	if err != nil {
		return fmt.Errorf("failed to count rows to delete: %w", err)
	}
	count := preview[cleanModeTableName(sel)]
	total := preview.Total()

	if count == 0 && total == 0 {
		fmt.Fprintf(os.Stderr, "%s No rows match the selection (%s).\n",
			terminal.InfoSymbol(), sel.describeScope())
		if globalJSON {
			return emitDBClean(cmd, sel, cleanCountsView(sel, preview), 0, 0, false)
		}
		return nil
	}

	printCleanPreview(sel, preview)

	if cleanDryRun {
		fmt.Fprintf(os.Stderr, "\n%s Dry-run: nothing was deleted.\n", terminal.InfoSymbol())
		if globalJSON {
			return emitDBClean(cmd, sel, cleanCountsView(sel, preview), total, 0, false)
		}
		return nil
	}

	if done, err := handleConfirmation(sel.describeAction(count)); done {
		if err == nil && globalJSON {
			return emitDBClean(cmd, sel, cleanCountsView(sel, preview), total, 0, true)
		}
		return err
	}

	deleted, err := applySelection(ctx, del, sel, false)
	if err != nil {
		return fmt.Errorf("failed to delete: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Deleted %d row(s): %s.", deleted.Total(), describeCounts(sel, deleted))))

	// Orphan cleanup removes rows the file had already stopped indexing; a
	// VACUUM there rewrites the whole database for very little reclaimed space,
	// so it stays opt-out-by-default as it was.
	if sel.Mode != cleanModeOrphans {
		runVacuum(ctx, db)
	}
	if globalJSON {
		return emitDBClean(cmd, sel, cleanCountsView(sel, deleted), total, deleted.Total(), false)
	}
	return nil
}

// describeCounts renders per-table counts on one line ("12 http_records, 22
// findings").
func describeCounts(sel *cleanSelection, counts database.DeleteCounts) string {
	parts := []string{}
	for _, it := range cleanCountsView(sel, counts) {
		parts = append(parts, fmt.Sprintf("%d %s", it.Rows, it.Table))
	}
	return strings.Join(parts, ", ")
}

// printCleanPreview states what will be deleted and, crucially, the scope it
// will be deleted from. The scope line is unconditional: a store-wide mode that
// looks narrow on the command line is exactly the case this command got wrong.
func printCleanPreview(sel *cleanSelection, counts database.DeleteCounts) {
	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(),
		terminal.Yellow(fmt.Sprintf("This will delete %d row(s) from %s:", counts.Total(), sel.describeScope())))
	for _, it := range cleanCountsView(sel, counts) {
		fmt.Fprintf(os.Stderr, "  - %-24s %d row(s)\n", it.Table, it.Rows)
	}

	switch sel.Mode {
	case cleanModeRecords:
		fmt.Fprintf(os.Stderr, "  %s HTTP records and their associated findings.\n", terminal.InfoSymbol())
	case cleanModeFindings:
		fmt.Fprintf(os.Stderr, "  %s Findings only; HTTP records are kept.\n", terminal.InfoSymbol())
	case cleanModeOrphans:
		fmt.Fprintf(os.Stderr, "  %s Findings whose HTTP records no longer exist.\n", terminal.InfoSymbol())
	case cleanModeTable:
		fmt.Fprintf(os.Stderr, "  %s Every row of table %q, for every project.\n",
			terminal.InfoSymbol(), sel.Table)
	}

	if active := describeActiveFilters(sel); active != "" {
		fmt.Fprintf(os.Stderr, "  %s Filters: %s\n", terminal.InfoSymbol(), active)
	}
}

// describeActiveFilters renders the filters that were actually applied, so the
// preview can be checked against the command line rather than trusted. It uses
// the shared filterSummary so the echo quotes and formats values exactly the way
// `finding` and `traffic` do.
func describeActiveFilters(sel *cleanSelection) string {
	f := sel.Filters
	var fs filterSummary
	fs.add("host", f.HostPattern)
	fs.add("scan-uuid", f.ScanUUID)
	if f.DateTo != nil {
		fs.add("before", f.DateTo.Format(time.RFC3339))
	}
	fs.addSeverities("severity", f.Severity)
	fs.addInts("status", f.StatusCodes)
	fs.addQuoted("search", f.SearchTerm)
	return fs.String()
}

// cleanAllTables truncates every data table. It reports per-table counts, so it
// keeps its own renderer rather than folding into runScopedClean.
func cleanAllTables(ctx context.Context, cmd *cobra.Command, db *database.DB, sel *cleanSelection) error {
	del := database.NewDeleteBuilder(db, database.QueryFilters{})
	counts, err := del.DeleteAllTables(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	var total int64
	items := []dbCleanView{}
	for _, tbl := range database.AllTablesDeleteOrder() {
		if c := counts[tbl]; c > 0 {
			total += c
			items = append(items, dbCleanView{Table: tbl, Rows: c})
		}
	}

	if total == 0 {
		fmt.Fprintf(os.Stderr, "%s All data tables are already empty.\n", terminal.InfoSymbol())
		if globalJSON {
			return emitDBClean(cmd, sel, items, 0, 0, false)
		}
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.WarningSymbol(),
		terminal.Yellow(fmt.Sprintf("This will delete ALL data from %s:", sel.describeScope())))
	for _, tbl := range database.AllTablesDeleteOrder() {
		if c := counts[tbl]; c > 0 {
			fmt.Fprintf(os.Stderr, "  - %-24s %d row(s)\n", tbl, c)
		}
	}
	fmt.Fprintf(os.Stderr, "  %s Total: %d row(s)\n", terminal.InfoSymbol(), total)

	if cleanDryRun {
		fmt.Fprintf(os.Stderr, "\n%s Dry-run: nothing was deleted.\n", terminal.InfoSymbol())
		if globalJSON {
			return emitDBClean(cmd, sel, items, total, 0, false)
		}
		return nil
	}

	// resolveCleanSelection already required --force for --all, so this cannot
	// prompt; the call is kept so every delete path goes through one gate.
	if done, err := handleConfirmation(sel.describeAction(total)); done {
		if err == nil && globalJSON {
			return emitDBClean(cmd, sel, items, total, 0, true)
		}
		return err
	}

	if _, err := del.DeleteAllTables(ctx, false); err != nil {
		return fmt.Errorf("failed to delete all records: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n", terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Deleted %d row(s) from all data tables.", total)))

	runVacuum(ctx, db)
	if globalJSON {
		return emitDBClean(cmd, sel, items, total, total, false)
	}
	return nil
}

// runVacuum reclaims disk space after deletion. Only applies to SQLite.
func runVacuum(ctx context.Context, db *database.DB) {
	if db.Driver() != "sqlite" {
		return
	}
	_, _ = fmt.Fprintf(humanOut(), "%s Running VACUUM to reclaim disk space...\n", terminal.InfoSymbol())
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		zap.L().Warn("VACUUM failed", zap.Error(err))
		return
	}
	_, _ = fmt.Fprintf(humanOut(), "%s %s\n", terminal.SuccessSymbol(), terminal.Green("VACUUM completed."))
}

// resetDatabase deletes the SQLite database file and recreates it with a fresh schema.
func resetDatabase() (dbResetView, error) {
	// config.LoadSettings directly, and ANY error refuses — not the clicommon
	// helper, which degrades a merely-discovered broken config to defaults.
	//
	// This function deletes a database file. The config is what names which one,
	// so falling back to defaults here does not mean "run with default settings",
	// it means "delete ~/.vigolium/database-vgnm.sqlite instead of the file you
	// configured". There is no reading of a broken config that justifies guessing
	// at that.
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		return dbResetView{}, fmt.Errorf("cannot determine which database to reset: %w", err)
	}

	if !settings.Database.Enabled && settings.Database.Driver == "" {
		settings.Database.Enabled = true
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = "~/.vigolium/database-vgnm.sqlite"
	}
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	if settings.Database.Driver != "sqlite" {
		return dbResetView{}, fmt.Errorf("database reset is only supported for SQLite (current driver: %s)", settings.Database.Driver)
	}

	dbPath := config.ExpandPath(settings.Database.SQLite.Path)

	// Close existing connection if open
	clicommon.ResetDBCache()

	// Remove the database file and its WAL/SHM companions
	removed := 0
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				return dbResetView{}, fmt.Errorf("failed to remove %s: %w", p, err)
			}
			removed++
		}
	}

	if removed == 0 {
		_, _ = fmt.Fprintf(humanOut(), "%s No database file found at %s\n", terminal.InfoSymbol(), terminal.Cyan(dbPath))
	} else {
		_, _ = fmt.Fprintf(humanOut(), "%s Deleted database file: %s\n", terminal.SuccessSymbol(), terminal.Cyan(dbPath))
	}

	// Recreate with fresh schema
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return dbResetView{}, fmt.Errorf("failed to create new database: %w", err)
	}
	clicommon.SetDBCache(db)

	if err := db.EnsureSchemaReady(context.Background()); err != nil {
		return dbResetView{}, fmt.Errorf("failed to create schema: %w", err)
	}

	_, _ = fmt.Fprintf(humanOut(), "%s %s %s\n", terminal.SuccessSymbol(), terminal.Green("Database recreated at"), terminal.Cyan(dbPath))
	return dbResetView{Path: dbPath, FilesRemoved: removed}, nil
}
