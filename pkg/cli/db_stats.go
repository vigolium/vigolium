package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show database statistics",
	RunE:  runDBStats,
}

var (
	statsDetailed bool
	statsScanUUID string
	statsHost     string
)

func init() {
	dbCmd.AddCommand(dbStatsCmd)

	dbStatsCmd.Flags().BoolVar(&statsDetailed, "detailed", false, "Show per-host and per-module breakdown")
	dbStatsCmd.Flags().StringVar(&statsScanUUID, "scan-id", "", "Show statistics for a specific scan session")
	dbStatsCmd.Flags().StringVar(&statsHost, "host", "", "Show statistics for a specific hostname")
}

func runDBStats(cmd *cobra.Command, args []string) error {
	// Ensure database is closed on exit
	defer closeDatabaseOnExit()

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
			// JSON output
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(stats); err != nil {
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
