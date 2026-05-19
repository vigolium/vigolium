package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

var dbCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean database records",
	Long:  "Delete records from the database by host, scan ID, age, status, or severity. Supports --dry-run to preview, --orphans to remove orphaned findings, and --vacuum to reclaim disk space after a delete.",
	RunE:  runDBClean,
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

	dbCleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Delete all records (requires --force)")
	dbCleanCmd.Flags().StringVar(&cleanHost, "host", "", "Delete records matching the specified hostname")
	dbCleanCmd.Flags().StringVar(&cleanScanUUID, "scan-uuid", "", "Delete records belonging to the specified scan UUID")
	dbCleanCmd.Flags().StringVar(&cleanBefore, "before", "", "Delete records created before this date (YYYY-MM-DD)")
	dbCleanCmd.Flags().IntSliceVar(&cleanStatus, "status", nil, "Delete records with matching HTTP status codes")
	dbCleanCmd.Flags().StringVar(&cleanSeverity, "severity", "", "Delete findings matching the specified severity level")

	dbCleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "Show what would be deleted without deleting")

	dbCleanCmd.Flags().BoolVar(&cleanOrphans, "orphans", false, "Delete findings with no matching HTTP record")

	dbCleanCmd.Flags().BoolVar(&cleanFindings, "findings-only", false, "Delete findings only, keep HTTP records")
	dbCleanCmd.Flags().StringVar(&cleanTable, "table", "", "Delete all rows from a specific table (e.g., http_records, findings, scans)")
}

func runDBClean(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// When --force is used without any filter flags, delete the database file and recreate it
	noFilters := !cleanAll && cleanHost == "" && cleanScanUUID == "" && cleanBefore == "" &&
		len(cleanStatus) == 0 && cleanSeverity == "" && !cleanOrphans && !cleanFindings && cleanTable == ""
	if globalForce && noFilters {
		return resetDatabase()
	}

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx := context.Background()

	if cleanOrphans {
		return cleanOrphanedRecords(ctx, db)
	}

	if cleanFindings {
		return cleanFindingsOnly(ctx, db)
	}

	if cleanTable != "" {
		return cleanSpecificTable(ctx, db)
	}

	if cleanAll {
		if !globalForce {
			return fmt.Errorf("--all requires --force flag for safety")
		}
		return cleanAllTables(ctx, db)
	}

	// Build filters
	var dateFrom *time.Time
	if cleanBefore != "" {
		t, err := parseDate(cleanBefore)
		if err != nil {
			return fmt.Errorf("invalid --before date: %w", err)
		}
		dateFrom = &t
	}

	var severities []string
	if cleanSeverity != "" {
		severities = strings.Split(cleanSeverity, ",")
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	filters := database.QueryFilters{
		ProjectUUID: projectUUID,
		HostPattern: cleanHost,
		StatusCodes: cleanStatus,
		ScanUUID:    cleanScanUUID,
		DateTo:      dateFrom,
		Severity:    severities,
		SearchTerm:  dbSearch,
	}

	delBuilder := database.NewDeleteBuilder(db, filters)

	count, err := delBuilder.DeleteRecords(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	if count == 0 {
		fmt.Printf("%s No records match the specified criteria.\n", terminal.InfoSymbol())
		return nil
	}

	msg := fmt.Sprintf("This will delete %d record(s)", count)
	if cleanHost != "" {
		msg += fmt.Sprintf(" from host: %s", cleanHost)
	}
	if cleanBefore != "" {
		msg += fmt.Sprintf(" before: %s", cleanBefore)
	}
	fmt.Printf("%s %s\n", terminal.WarningSymbol(), terminal.Yellow(msg))

	fmt.Printf("  %s Associated findings will also be deleted.\n", terminal.InfoSymbol())

	if cleanDryRun {
		fmt.Printf("\n%s Dry-run mode: No records were deleted.\n", terminal.InfoSymbol())
		return nil
	}

	if !globalForce {
		fmt.Print("\nProceed? (type 'yes' to confirm): ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	deleted, err := delBuilder.DeleteRecords(ctx, false)
	if err != nil {
		return fmt.Errorf("failed to delete records: %w", err)
	}

	fmt.Printf("\n%s %s\n", terminal.SuccessSymbol(), terminal.Green(fmt.Sprintf("Deleted %d record(s) successfully.", deleted)))

	runVacuum(ctx, db)
	return nil
}

func cleanSpecificTable(ctx context.Context, db *database.DB) error {
	if _, ok := database.AllowedCleanTables[cleanTable]; !ok {
		allowed := make([]string, 0, len(database.AllowedCleanTables))
		for k := range database.AllowedCleanTables {
			allowed = append(allowed, k)
		}
		sort.Strings(allowed)
		return fmt.Errorf("table %q is not allowed for cleaning. Allowed tables: %s", cleanTable, strings.Join(allowed, ", "))
	}

	delBuilder := database.NewDeleteBuilder(db, database.QueryFilters{})
	count, err := delBuilder.DeleteTable(ctx, cleanTable, true)
	if err != nil {
		return err
	}

	if count == 0 {
		fmt.Printf("%s Table %q is already empty.\n", terminal.InfoSymbol(), cleanTable)
		return nil
	}

	fmt.Printf("%s %s\n", terminal.WarningSymbol(),
		terminal.Yellow(fmt.Sprintf("This will delete %d row(s) from table %q.", count, cleanTable)))

	if cleanDryRun {
		fmt.Printf("\n%s Dry-run mode: No records were deleted.\n", terminal.InfoSymbol())
		return nil
	}

	if !globalForce {
		fmt.Print("\nProceed? (type 'yes' to confirm): ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(response)) != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	deleted, err := delBuilder.DeleteTable(ctx, cleanTable, false)
	if err != nil {
		return fmt.Errorf("failed to clean table %q: %w", cleanTable, err)
	}

	fmt.Printf("\n%s %s\n", terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Deleted %d row(s) from table %q.", deleted, cleanTable)))

	runVacuum(ctx, db)
	return nil
}

func cleanAllTables(ctx context.Context, db *database.DB) error {
	delBuilder := database.NewDeleteBuilder(db, database.QueryFilters{})
	counts, err := delBuilder.DeleteAllTables(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to count records: %w", err)
	}

	var total int64
	for _, c := range counts {
		total += c
	}

	if total == 0 {
		fmt.Printf("%s All data tables are already empty.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("%s %s\n", terminal.WarningSymbol(),
		terminal.Yellow("This will delete ALL data from the following tables:"))
	for _, tbl := range database.AllTablesDeleteOrder() {
		if c := counts[tbl]; c > 0 {
			fmt.Printf("  - %-20s %d row(s)\n", tbl, c)
		}
	}
	fmt.Printf("  %s Total: %d row(s)\n", terminal.InfoSymbol(), total)

	if cleanDryRun {
		fmt.Printf("\n%s Dry-run mode: No records were deleted.\n", terminal.InfoSymbol())
		return nil
	}

	_, err = delBuilder.DeleteAllTables(ctx, false)
	if err != nil {
		return fmt.Errorf("failed to delete all records: %w", err)
	}

	fmt.Printf("\n%s %s\n", terminal.SuccessSymbol(),
		terminal.Green(fmt.Sprintf("Deleted %d row(s) from all data tables.", total)))

	runVacuum(ctx, db)
	return nil
}

func cleanOrphanedRecords(ctx context.Context, db *database.DB) error {
	fmt.Printf("%s Scanning for orphaned findings...\n", terminal.InfoSymbol())

	delBuilder := database.NewDeleteBuilder(db, database.QueryFilters{})
	count, err := delBuilder.DeleteOrphans(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to count orphans: %w", err)
	}

	if count == 0 {
		fmt.Printf("%s No orphaned findings found.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("%s %s\n", terminal.WarningSymbol(), terminal.Yellow(fmt.Sprintf("Found %d orphaned finding(s).", count)))

	if cleanDryRun {
		fmt.Printf("%s Dry-run mode: No records were deleted.\n", terminal.InfoSymbol())
		return nil
	}

	if !globalForce {
		fmt.Print("Delete orphaned findings? (type 'yes' to confirm): ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	deleted, err := delBuilder.DeleteOrphans(ctx, false)
	if err != nil {
		return fmt.Errorf("failed to delete orphans: %w", err)
	}

	fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green(fmt.Sprintf("Deleted %d orphaned finding(s) successfully.", deleted)))
	return nil
}

func cleanFindingsOnly(ctx context.Context, db *database.DB) error {
	var severities []string
	if cleanSeverity != "" {
		severities = strings.Split(cleanSeverity, ",")
	}

	query := db.NewDelete().Model((*database.Finding)(nil))

	if len(severities) > 0 {
		query = query.Where("severity IN (?)", severities)
	}

	countQuery := db.NewSelect().Model((*database.Finding)(nil))
	if len(severities) > 0 {
		countQuery = countQuery.Where("severity IN (?)", severities)
	}

	count, err := countQuery.Count(ctx)
	if err != nil {
		return fmt.Errorf("failed to count findings: %w", err)
	}

	if count == 0 {
		fmt.Printf("%s No findings match the specified criteria.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("%s %s\n", terminal.WarningSymbol(), terminal.Yellow(fmt.Sprintf("This will delete %d finding(s).", count)))

	if cleanDryRun {
		fmt.Printf("%s Dry-run mode: No records were deleted.\n", terminal.InfoSymbol())
		return nil
	}

	if !globalForce {
		fmt.Print("Proceed? (type 'yes' to confirm): ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	result, err := query.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete findings: %w", err)
	}

	deleted, _ := result.RowsAffected()
	fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green(fmt.Sprintf("Deleted %d finding(s) successfully.", deleted)))
	return nil
}

// runVacuum reclaims disk space after deletion. Only applies to SQLite.
func runVacuum(ctx context.Context, db *database.DB) {
	if db.Driver() != "sqlite" {
		return
	}
	fmt.Printf("%s Running VACUUM to reclaim disk space...\n", terminal.InfoSymbol())
	if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
		zap.L().Warn("VACUUM failed", zap.Error(err))
		return
	}
	fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green("VACUUM completed."))
}

// resetDatabase deletes the SQLite database file and recreates it with a fresh schema.
func resetDatabase() error {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
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
		return fmt.Errorf("database reset is only supported for SQLite (current driver: %s)", settings.Database.Driver)
	}

	dbPath := config.ExpandPath(settings.Database.SQLite.Path)

	// Close existing connection if open
	if dbConnection != nil {
		_ = dbConnection.Close()
		dbConnection = nil
	}

	// Remove the database file and its WAL/SHM companions
	removed := 0
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf("failed to remove %s: %w", p, err)
			}
			removed++
		}
	}

	if removed == 0 {
		fmt.Printf("%s No database file found at %s\n", terminal.InfoSymbol(), terminal.Cyan(dbPath))
	} else {
		fmt.Printf("%s Deleted database file: %s\n", terminal.SuccessSymbol(), terminal.Cyan(dbPath))
	}

	// Recreate with fresh schema
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create new database: %w", err)
	}
	dbConnection = db

	if err := db.CreateSchema(context.Background()); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	fmt.Printf("%s %s %s\n", terminal.SuccessSymbol(), terminal.Green("Database recreated at"), terminal.Cyan(dbPath))
	return nil
}
