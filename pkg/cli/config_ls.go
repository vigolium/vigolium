package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var configLsCmd = &cobra.Command{
	Use:     "ls [filter]",
	Aliases: []string{"list", "view"},
	Short:   "Display current configuration",
	Long:    "Display current configuration settings. Optionally filter by key substring.",
	RunE:    runConfigLs,
}

func init() {
	configCmd.AddCommand(configLsCmd)
}

func runConfigLs(cmd *cobra.Command, args []string) error {
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	entries := config.FlattenSettings(settings)

	// Sort entries by key for stable output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	// Apply filter if provided
	filter := ""
	if len(args) > 0 {
		filter = strings.ToLower(args[0])
	}

	count := 0
	for _, entry := range entries {
		if filter != "" && !strings.Contains(strings.ToLower(entry.Key), filter) {
			continue
		}

		displayValue := entry.Value
		if entry.Sensitive && !globalForce {
			if entry.Value != "" && entry.Value != "<nil>" {
				displayValue = "[redacted]"
			} else {
				displayValue = "(empty)"
			}
		} else if entry.Value == "" || entry.Value == "<nil>" {
			displayValue = "(empty)"
		}

		colorFn := sectionKeyColor(entry.Key)
		fmt.Printf("%s = %s\n", colorFn(entry.Key), displayValue)
		count++
	}

	if count == 0 {
		if filter != "" {
			fmt.Printf("%s No config keys matching %q\n", terminal.WarnPrefix(), filter)
		} else {
			fmt.Printf("%s No configuration found\n", terminal.WarnPrefix())
		}
		return nil
	}

	if filter == "" {
		fmt.Println()
		fmt.Printf("%s Config file: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(effectiveConfigPath())))
	}

	return nil
}

// sectionKeyColor returns a color function based on the top-level config section.
func sectionKeyColor(key string) func(string) string {
	section, _, _ := strings.Cut(key, ".")
	switch section {
	case "server":
		return terminal.Cyan
	case "database":
		return terminal.Blue
	case "notify":
		return terminal.Yellow
	case "audit":
		return terminal.Green
	case "mutation_strategy":
		return terminal.Teal
	case "scope":
		return terminal.HiGreen
	case "scanning_pace":
		return terminal.Magenta
	default:
		return terminal.Cyan
	}
}
