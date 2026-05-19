package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var scopeSetCmd = &cobra.Command{
	Use:   "set <component.field> <value>",
	Short: "Set a scope rule",
	Long:  "Set a scope rule using component.field notation (e.g. host.exclude \"*.internal.com,admin.*\").",
	Args:  cobra.ExactArgs(2),
	RunE:  runScopeSet,
}

func init() {
	scopeCmd.AddCommand(scopeSetCmd)
}

func runScopeSet(cmd *cobra.Command, args []string) error {
	key := "scope." + args[0]
	value := args[1]

	// Load current settings
	configPath := effectiveConfigPath()
	settings, err := config.LoadSettings(globalConfig)
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
