package cli

import (
	"fmt"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long:  "Set a configuration value using dot-notation key (e.g. notify.enabled true).\nAlso accepts 'key = value' format copied from 'config ls' output.",
	Args:  cobra.RangeArgs(2, 3),
	RunE:  runConfigSet,
}

func init() {
	configCmd.AddCommand(configSetCmd)
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	var key, value string
	if len(args) == 3 && args[1] == "=" {
		// Support "key = value" format (copied from config ls output)
		key = args[0]
		value = args[2]
	} else if len(args) == 2 {
		key = args[0]
		value = args[1]
	} else {
		return fmt.Errorf("usage: config set <key> <value> or config set <key> = <value>")
	}

	// Load current settings
	configPath := config.ConfigFilePath()
	settings, err := config.LoadSettings("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Update the field
	if err := config.SetField(settings, key, value); err != nil {
		return fmt.Errorf("failed to set %q: %w", key, err)
	}

	// Save back to file
	if err := config.SaveSettings(configPath, settings); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("%s Set %s = %s\n", terminal.SuccessSymbol(), terminal.Cyan(key), value)
	return nil
}
