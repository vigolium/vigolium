package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var dbCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean database records",
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
	cleanVacuum   bool
	cleanOrphans  bool
	cleanFindings bool
)

func init() {
	dbCmd.AddCommand(dbCleanCmd)

	dbCleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Delete all records from the database (requires --force)")
	dbCleanCmd.Flags().StringVar(&cleanHost, "host", "", "Delete records matching the specified hostname")
	dbCleanCmd.Flags().StringVar(&cleanScanUUID, "scan-id", "", "Delete records belonging to the specified scan session")
	dbCleanCmd.Flags().StringVar(&cleanBefore, "before", "", "Delete records created before this date (YYYY-MM-DD)")
	dbCleanCmd.Flags().IntSliceVar(&cleanStatus, "status", nil, "Delete records with matching HTTP status codes")
	dbCleanCmd.Flags().StringVar(&cleanSeverity, "severity", "", "Delete findings matching the specified severity level")

	dbCleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "Preview what would be deleted without making changes")
	dbCleanCmd.Flags().BoolVar(&cleanVacuum, "vacuum", false, "Reclaim disk space after deletion (SQLite only)")

	dbCleanCmd.Flags().BoolVar(&cleanOrphans, "orphans", false, "Delete orphaned findings that have no matching records")

	dbCleanCmd.Flags().BoolVar(&cleanFindings, "findings-only", false, "Delete only findings while keeping HTTP records intact")
}

func runDBClean(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	// When --force is used without any filter flags, delete the database file and recreate it
	noFilters := !cleanAll && cleanHost == "" && cleanScanUUID == "" && cleanBefore == "" &&
		len(cleanStatus) == 0 && cleanSeverity == "" && !cleanOrphans && !cleanFindings
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

	filters := database.QueryFilters{
		HostPattern: cleanHost,
		StatusCodes: cleanStatus,
		DateTo:      dateFrom,
		Severity:    severities,
		SearchTerm:  dbSearch,
	}

	if cleanAll {
		if !globalForce {
			return fmt.Errorf("--all requires --force flag for safety")
		}
		filters = database.QueryFilters{}
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
	if cleanAll {
		msg += " (ALL RECORDS)"
	}
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

	if cleanVacuum && db.Driver() == "sqlite" {
		fmt.Printf("\n%s Running VACUUM to reclaim disk space...\n", terminal.InfoSymbol())
		if _, err := db.ExecContext(ctx, "VACUUM"); err != nil {
			return fmt.Errorf("failed to run VACUUM: %w", err)
		}
		fmt.Printf("%s %s\n", terminal.SuccessSymbol(), terminal.Green("VACUUM completed successfully."))
	}

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
