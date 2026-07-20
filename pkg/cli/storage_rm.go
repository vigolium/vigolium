package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageRmCmd = &cobra.Command{
	Use:     "rm <key> [<key>...]",
	Aliases: []string{"delete"},
	Short:   "Delete one or more objects from cloud storage",
	Long:    "Permanently delete objects from the active project's storage. Prompts for confirmation unless --force is set.",
	Args:    cobra.MinimumNArgs(1),
	RunE:    runStorageRm,
}

func init() {
	storageCmd.AddCommand(storageRmCmd)
}

func runStorageRm(_ *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	fmt.Printf("%s Will delete %d object(s) from project %s:\n",
		terminal.WarningSymbol(), len(args), terminal.Cyan(projectUUID))
	for _, key := range args {
		fmt.Printf("  - %s\n", terminal.Gray(key))
	}

	if !globalForce {
		fmt.Print("\nProceed? (type 'yes' to confirm): ")
		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		if strings.TrimSpace(strings.ToLower(response)) != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	ctx := context.Background()
	var failures int
	for _, key := range args {
		if err := sc.Delete(ctx, projectUUID, key); err != nil {
			failures++
			fmt.Printf("%s %s: %s\n", terminal.ErrorSymbol(), terminal.Gray(key), err)
			continue
		}
		fmt.Printf("%s Deleted %s\n", terminal.SuccessSymbol(), terminal.Gray(key))
	}

	if failures > 0 {
		return fmt.Errorf("%d of %d deletion(s) failed", failures, len(args))
	}
	return nil
}
