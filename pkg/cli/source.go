package cli

import (
	"context"
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var sourceCmd = &cobra.Command{
	Use:     "source",
	Aliases: []string{"src"},
	Short:   "Manage application source code links",
	RunE:    runSourceList,
}

var sourceLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List linked source repos",
	RunE:    runSourceList,
}

func init() {
	rootCmd.AddCommand(sourceCmd)
	sourceCmd.AddCommand(sourceLsCmd)
}

func runSourceList(_ *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return err
	}

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	repo := database.NewRepository(db)
	repos, total, err := repo.ListSourceRepos(ctx, resolveProjectUUID(), 100, 0)
	if err != nil {
		return fmt.Errorf("failed to list source repos: %w", err)
	}

	if total == 0 {
		fmt.Printf("%s No source repos linked. Use %s to add one.\n",
			terminal.InfoSymbol(), terminal.Cyan("vigolium source add"))
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "ID", "HOSTNAME", "NAME", "PATH", "LANGUAGE", "FRAMEWORK", "TYPE", "SCAN STATUS")
	for _, sr := range repos {
		lang := sr.Language
		if lang == "" {
			lang = "-"
		}
		fw := sr.Framework
		if fw == "" {
			fw = "-"
		}
		scanStatus := sr.ThirdPartyScanStatus
		if scanStatus == "" {
			scanStatus = "-"
		}
		if !sr.ThirdPartyScanAt.IsZero() {
			scanStatus += " (" + sr.ThirdPartyScanAt.Format("Jan 02 15:04") + ")"
		}
		tbl.AddRow(
			fmt.Sprintf("%d", sr.ID),
			terminal.Cyan(sr.Hostname),
			sr.Name,
			terminal.Gray(sr.RootPath),
			lang,
			fw,
			sr.RepoType,
			scanStatus,
		)
	}
	tbl.Print()

	fmt.Printf("\n%s Total: %d source repo(s)\n", terminal.InfoSymbol(), total)
	return nil
}
