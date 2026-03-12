package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	sessionMode   string
	sessionLimit  int
	sessionOffset int
)

var agentSessionCmd = &cobra.Command{
	Use:     "session",
	Aliases: []string{"sessions"},
	Short:   "List agent run sessions",
	RunE:    runAgentSession,
}

func init() {
	agentCmd.AddCommand(agentSessionCmd)

	agentSessionCmd.Flags().StringVar(&sessionMode, "mode", "", "Filter by mode (query, autopilot, pipeline, swarm)")
	agentSessionCmd.Flags().IntVarP(&sessionLimit, "limit", "n", 50, "Maximum number of records to display")
	agentSessionCmd.Flags().IntVarP(&sessionOffset, "offset", "o", 0, "Number of records to skip")
}

func runAgentSession(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
		return fmt.Errorf("failed to create schema: %w", schemaErr)
	}

	repo := database.NewRepository(db)
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	runs, total, err := repo.ListAgentRuns(ctx, projectUUID, sessionMode, sessionLimit, sessionOffset)
	if err != nil {
		return fmt.Errorf("failed to list agent sessions: %w", err)
	}

	if globalJSON {
		output := map[string]interface{}{
			"total":    total,
			"offset":   sessionOffset,
			"limit":    sessionLimit,
			"sessions": runs,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	if len(runs) == 0 {
		fmt.Printf("%s No agent sessions found.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("Showing %d-%d of %d agent sessions\n\n",
		sessionOffset+1,
		min(sessionOffset+len(runs), int(total)),
		total)

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "UUID", "MODE", "AGENT", "STATUS", "SESSION ID", "TARGET", "FINDINGS", "RECORDS", "PHASE", "DURATION", "CREATED")
	for _, r := range runs {
		status := r.Status
		switch status {
		case "completed":
			status = terminal.Green(status)
		case "running":
			status = terminal.Cyan(status)
		case "failed":
			status = terminal.Red(status)
		case "cancelled":
			status = terminal.Yellow(status)
		case "pending":
			status = terminal.Gray(status)
		}

		duration := ""
		if r.DurationMs > 0 {
			duration = fmt.Sprintf("%.1fs", float64(r.DurationMs)/1000)
		} else if !r.StartedAt.IsZero() && r.CompletedAt.IsZero() {
			duration = fmt.Sprintf("%.1fs…", time.Since(r.StartedAt).Seconds())
		}

		target := r.TargetURL
		if len(target) > 40 {
			target = target[:37] + "..."
		}

		uuid := r.UUID
		if len(uuid) > 8 {
			uuid = uuid[:8]
		}

		sid := r.SessionID
		if len(sid) > 12 {
			sid = sid[:12] + "…"
		}

		phase := r.CurrentPhase

		created := r.CreatedAt.Format("2006-01-02 15:04")

		tbl.AddRow(
			terminal.Gray(uuid),
			terminal.Cyan(r.Mode),
			r.AgentName,
			status,
			terminal.Gray(sid),
			target,
			fmt.Sprintf("%d", r.FindingCount),
			fmt.Sprintf("%d", r.RecordCount),
			phase,
			duration,
			terminal.Gray(created),
		)
	}
	tbl.Print()
	fmt.Println()
	return nil
}
