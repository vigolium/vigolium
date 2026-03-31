package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var importCmd = &cobra.Command{
	Use:   "import <archon-output-folder>",
	Short: "Import archon audit output into the database",
	Long: `Import findings and audit metadata from an archon output folder.

The folder must contain audit-state.json and a findings-draft/ directory.
Creates an AgentRun record for the audit and imports all findings.

Example:
  vigolium import /path/to/archon-output-harbor/`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	folderPath := args[0]

	// Validate folder exists
	info, err := os.Stat(folderPath)
	if err != nil {
		return fmt.Errorf("cannot access folder: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", folderPath)
	}

	// Parse the archon output folder
	result, err := archon.ParseAuditFolder(folderPath)
	if err != nil {
		return fmt.Errorf("failed to parse archon output: %w", err)
	}

	// Connect to database
	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	ctx := context.Background()
	repo := database.NewRepository(db)

	// Build and create AgentRun
	agentRun := archon.BuildAgentRun(result.State, folderPath, projectUUID)
	if err := repo.CreateAgentRun(ctx, agentRun); err != nil {
		return fmt.Errorf("failed to create agent run: %w", err)
	}

	// Build and save findings
	auditID := result.State.Audits[0].AuditID
	findings := archon.BuildFindings(result.RawFindings, auditID, agentRun.UUID, projectUUID)

	saved, skipped := 0, 0
	for _, f := range findings {
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			skipped++
			continue
		}
		if f.ID == 0 {
			skipped++
		} else {
			saved++
		}
	}

	// Update agent run with actual saved count
	agentRun.SavedCount = saved
	agentRun.FindingCount = len(findings)
	_ = repo.UpdateAgentRun(ctx, agentRun)

	// Count severity distribution
	sevCounts := map[string]int{}
	for _, f := range findings {
		sevCounts[f.Severity]++
	}

	if globalJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"agent_run_uuid": agentRun.UUID,
			"total":          len(findings),
			"saved":          saved,
			"skipped":        skipped,
			"severity":       sevCounts,
		})
	}

	fmt.Printf("%s Imported archon audit: %d findings (%d new, %d duplicates skipped)\n",
		terminal.SuccessSymbol(), len(findings), saved, skipped)
	fmt.Printf("  Agent run: %s (mode=%s, status=%s)\n", agentRun.UUID, agentRun.Mode, agentRun.Status)
	if sevCounts["high"] > 0 || sevCounts["critical"] > 0 || sevCounts["medium"] > 0 || sevCounts["low"] > 0 {
		fmt.Printf("  Severity: %s, %s, %s, %s\n",
			terminal.BoldMagenta(fmt.Sprintf("%d critical", sevCounts["critical"])),
			terminal.BoldRed(fmt.Sprintf("%d high", sevCounts["high"])),
			terminal.BoldYellow(fmt.Sprintf("%d medium", sevCounts["medium"])),
			terminal.BoldGreen(fmt.Sprintf("%d low", sevCounts["low"])),
		)
	}
	return nil
}
