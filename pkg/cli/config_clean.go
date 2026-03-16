package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var configCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Reset Vigolium to a clean state",
	Long:  "Remove the ~/.vigolium/ directory (config, database, extensions) and regenerate fresh defaults.",
	RunE:  runConfigClean,
}

func init() {
	configCmd.AddCommand(configCleanCmd)
}

func runConfigClean(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	vigoliumDir := filepath.Join(homeDir, ".vigolium")

	displayDir := config.ContractPath(vigoliumDir)

	// Check if directory exists
	if _, err := os.Stat(vigoliumDir); os.IsNotExist(err) {
		fmt.Printf("%s Nothing to clean — %s does not exist.\n", terminal.InfoSymbol(), displayDir)
		return nil
	}

	fmt.Printf("%s This will remove %s (config, database, and all local data)\n", terminal.BoldRed(terminal.SymbolFailed+" Warn:"), terminal.Cyan(displayDir))

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

	if err := os.RemoveAll(vigoliumDir); err != nil {
		return fmt.Errorf("failed to remove %s: %w", vigoliumDir, err)
	}

	fmt.Printf("%s Removed %s\n", terminal.SuccessSymbol(), displayDir)

	// Regenerate fresh defaults
	if err := initializeVigolium(); err != nil {
		return fmt.Errorf("failed to reinitialize: %w", err)
	}

	return nil
}
