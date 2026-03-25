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

var (
	sessionLsHost string
)

var sessionLsCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List session authentication configs",
	RunE:    runSessionLs,
}

func init() {
	sessionCmd.AddCommand(sessionLsCmd)
	sessionLsCmd.Flags().StringVar(&sessionLsHost, "host", "", "Filter by hostname")
}

func runSessionLs(cmd *cobra.Command, args []string) error {
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

	var rows []*database.SessionHostname
	if sessionLsHost != "" {
		rows, err = repo.GetSessionHostnamesByHostname(ctx, projectUUID, sessionLsHost)
	} else {
		rows, err = repo.GetSessionHostnamesByProject(ctx, projectUUID)
	}
	if err != nil {
		return fmt.Errorf("failed to list session hostnames: %w", err)
	}

	if globalJSON {
		output := map[string]interface{}{
			"total":    len(rows),
			"sessions": rows,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	if len(rows) == 0 {
		fmt.Printf("%s No session auth configs found.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("%s %d session auth config(s)\n\n", terminal.InfoSymbol(), len(rows))

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "HOSTNAME", "SESSION NAME", "ROLE", "POS", "TOKEN", "EXTRACT RULES")
	for _, sh := range rows {
		role := sh.SessionRole
		switch role {
		case "primary":
			role = terminal.Green(role)
		case "compare":
			role = terminal.Yellow(role)
		}

		token := sh.SessionToken
		if token == "" {
			token = "–"
		} else if len(token) > 40 {
			token = token[:37] + "..."
		}

		extractRules := sh.ExtractRules
		if extractRules == "" {
			extractRules = "–"
		} else if len(extractRules) > 60 {
			extractRules = extractRules[:57] + "..."
		}

		tbl.AddRow(
			terminal.Cyan(sh.Hostname),
			sh.SessionName,
			role,
			fmt.Sprintf("%d", sh.Position),
			terminal.Gray(token),
			terminal.Gray(extractRules),
		)
	}
	tbl.Print()
	fmt.Println()
	return nil
}
