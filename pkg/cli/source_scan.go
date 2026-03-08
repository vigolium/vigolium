package cli

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/toolexec/sourcetools"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var sourceScanCmd = &cobra.Command{
	Use:   "scan <id>",
	Short: "Run third-party security tools against a source repo",
	Args:  cobra.ExactArgs(1),
	RunE:  runSourceScan,
}

func init() {
	sourceCmd.AddCommand(sourceScanCmd)
}

func runSourceScan(_ *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ID: %w", err)
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		settings = config.DefaultSettings()
	}

	if !settings.SourceAware.ThirdPartyIntegration.Enabled {
		fmt.Printf("%s Third-party integration is disabled in config\n", terminal.InfoSymbol())
		return nil
	}

	db, err := getDB()
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	repo := database.NewRepository(db)
	sr, err := repo.GetSourceRepoByID(ctx, id)
	if err != nil {
		return fmt.Errorf("source repo not found: %w", err)
	}

	fmt.Printf("%s Running third-party tools on %s (%s) ...\n",
		terminal.InfoSymbol(), terminal.Cyan(sr.Name), terminal.Gray(sr.RootPath))

	// Mark as running
	sr.ThirdPartyScanStatus = "running"
	sr.UpdatedAt = time.Now()
	_ = repo.UpdateSourceRepo(ctx, sr)

	runner := sourcetools.New(&settings.SourceAware.ThirdPartyIntegration, repo)
	result, runErr := runner.RunAll(ctx, sr)

	// Update scan status
	if runErr != nil {
		sr.ThirdPartyScanStatus = "failed"
		fmt.Printf("%s Third-party scan warning: %v\n", terminal.WarningSymbol(), runErr)
	} else {
		sr.ThirdPartyScanStatus = "completed"
	}
	sr.ThirdPartyScanAt = time.Now()
	_ = repo.UpdateSourceRepo(ctx, sr)

	printToolFindings(result)
	return nil
}

// printToolFindings prints a summary table of findings from third-party tools.
func printToolFindings(result *sourcetools.RunResult) {
	if len(result.Findings) == 0 {
		fmt.Printf("%s No findings from third-party tools\n", terminal.InfoSymbol())
		return
	}

	header := fmt.Sprintf("Third-party tool findings: %d", result.GroupedAt)
	if result.RawCount > result.GroupedAt {
		header += fmt.Sprintf(" (%d raw findings grouped)", result.RawCount)
	}
	fmt.Printf("\n%s %s\n\n", terminal.ResultSymbol(), header)

	tbl := terminal.NewTableWithMaxWidth(90, "TOOL", "SEVERITY", "LOCATIONS", "RULE/MESSAGE")
	for _, f := range result.Findings {
		tool := f.ModuleID
		location := ""
		if len(f.MatchedAt) > 0 {
			location = f.MatchedAt[0]
		}
		if len(f.MatchedAt) > 1 {
			location += fmt.Sprintf(" (+%d more)", len(f.MatchedAt)-1)
		}

		// Truncate description for table display
		desc := f.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}

		sevDisplay := severityDisplay(f.Severity)

		tbl.AddRow(tool, sevDisplay, location, desc)
	}
	tbl.Print()
	fmt.Println()
}

// severityDisplay returns a colored severity string.
func severityDisplay(sev string) string {
	switch sev {
	case "critical":
		return terminal.BoldMagenta("CRITICAL")
	case "high":
		return terminal.BoldRed("HIGH")
	case "medium":
		return terminal.BoldYellow("MEDIUM")
	case "low":
		return terminal.Green("LOW")
	default:
		return terminal.Blue("INFO")
	}
}
