package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show database statistics",
	Long:  "Print summary statistics for the database: counts of HTTP records, findings by severity, scans, and projects. Use --detailed to add per-host and per-module breakdowns, or --scan-uuid to scope to a single scan UUID.",
	RunE:  runDBStats,
}

var (
	statsDetailed bool
	statsScanUUID string
	statsHost     string
	statsFrom     string
	statsTo       string
)

func init() {
	dbCmd.AddCommand(dbStatsCmd)

	dbStatsCmd.Flags().BoolVar(&statsDetailed, "detailed", false, "Show per-host and per-module breakdown")
	dbStatsCmd.Flags().StringVar(&statsScanUUID, "scan-uuid", "", "Show statistics for a specific scan UUID")
	dbStatsCmd.Flags().StringVar(&statsHost, "host", "", "Show statistics for a specific hostname")
	registerTimeRangeFlags(dbStatsCmd, &statsFrom, &statsTo, "records sent, findings found and scans started")
}

func runDBStats(cmd *cobra.Command, args []string) error {
	// Ensure database is closed on exit
	defer closeDatabaseOnExit()

	dateFrom, dateTo, err := parseDateRangeFlags(statsFrom, statsTo, timeFilterFromLabel, timeFilterToLabel)
	if err != nil {
		return err
	}

	// Get database connection
	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	return runWithWatch(func() error {
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}

		// Build filters
		filters := database.QueryFilters{
			ProjectUUID: projectUUID,
			HostPattern: statsHost,
			ScanUUID:    statsScanUUID,
			DateFrom:    dateFrom,
			DateTo:      dateTo,
		}

		// Get statistics
		ctx := context.Background()
		stats, err := db.GetStats(ctx, filters)
		if err != nil {
			return fmt.Errorf("failed to get statistics: %w", err)
		}

		// Get top hosts if detailed mode
		if statsDetailed {
			topHosts, err := db.GetTopHosts(ctx, filters, 10)
			if err == nil {
				stats.TopHosts = topHosts
			}
		}

		// Output statistics
		if globalJSON {
			// `db stats -j` used to be a documented EXCEPTION to the -j contract:
			// it emitted its raw stats struct with no envelope, so a consumer had
			// to special-case it forever. A contract with a hole in it is not a
			// contract, so the struct now rides under `items` like every other
			// command's payload: one object, so items:[stats]. The legacy alias
			// `stats` (--json-legacy-keys) still renders the object itself.
			if err := emitObject(cmd, "stats", stats,
				withDBPath(resolvedReadDBPath()),
				withQuery("finding", "--json", "--min-severity", "high")); err != nil {
				return fmt.Errorf("failed to encode JSON: %w", err)
			}
		} else {
			// Human-readable output
			fmt.Print(database.FormatStats(stats))

			// Print top hosts if detailed mode with symbols and colors
			if statsDetailed && len(stats.TopHosts) > 0 {
				fmt.Printf("\n%s %s\n",
					terminal.SubSectionSymbol(),
					terminal.Bold("Top 10 Hosts by Request Count"))

				tbl := terminal.NewTableWithMaxWidth(globalWidth, "HOST", "REQUESTS", "FINDINGS")
				for _, h := range stats.TopHosts {
					host := fmt.Sprintf("%s://%s:%d", h.Scheme, h.Hostname, h.Port)
					tbl.AddRow(
						terminal.Cyan(host),
						terminal.Green(fmt.Sprintf("%d", h.RequestCount)),
						terminal.Yellow(fmt.Sprintf("%d", h.FindingCount)),
					)
				}
				tbl.Print()
				fmt.Println()
			}
		}

		return nil
	})
}
