package configcmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func newSetCmd(deps Deps, example string) *cobra.Command {
	return &cobra.Command{
		Use:     "set <key> <value>",
		Short:   "Set a configuration value",
		Long:    "Set a configuration value using dot-notation key (e.g. notify.enabled true).\nAlso accepts 'key = value' and 'key=value' formats.",
		Args:    cobra.RangeArgs(1, 3),
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigSet(deps, args)
		},
	}
}

func runConfigSet(deps Deps, args []string) error {
	var key, value string
	switch {
	case len(args) == 1 && strings.Contains(args[0], "="):
		// Support "key=value" format (single argument)
		k, v, _ := strings.Cut(args[0], "=")
		key = strings.TrimSpace(k)
		value = strings.TrimSpace(v)
		if key == "" {
			return fmt.Errorf("usage: config set <key>=<value>")
		}
	case len(args) == 3 && args[1] == "=":
		// Support "key = value" format (copied from config ls output)
		key = args[0]
		value = args[2]
	case len(args) == 2:
		key = args[0]
		value = args[1]
	default:
		return fmt.Errorf("usage: config set <key> <value> | config set <key>=<value> | config set <key> = <value>")
	}

	// Load current settings
	configPath := clicommon.EffectiveConfigPath(deps.ConfigFlag())
	settings, err := config.LoadSettings(deps.ConfigFlag())
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
