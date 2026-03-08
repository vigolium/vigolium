package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var scopeCmd = &cobra.Command{
	Use:     "scope",
	Aliases: []string{"sc"},
	Short:   "Manage scan scope rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScopeView(cmd, args)
	},
}

var scopeViewCmd = &cobra.Command{
	Use:     "view [component]",
	Aliases: []string{"ls", "list"},
	Short:   "Display current scope configuration",
	RunE:    runScopeView,
}

func init() {
	rootCmd.AddCommand(scopeCmd)
	scopeCmd.AddCommand(scopeViewCmd)
}

func runScopeView(cmd *cobra.Command, args []string) error {
	settings, err := config.LoadSettings("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	entries := config.FlattenSettings(settings)

	// Sort entries by key for stable output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Key < entries[j].Key
	})

	// Build filter: only show scope.* keys, optionally filtered by component
	filter := "scope."
	if len(args) > 0 {
		filter = "scope." + strings.ToLower(args[0])
	}

	count := 0
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Key), filter) {
			continue
		}

		displayValue := entry.Value
		if entry.Value == "" || entry.Value == "<nil>" {
			displayValue = "(empty)"
		}

		colorFn := scopeComponentColor(entry.Key)
		fmt.Printf("  %s = %s\n", colorFn(entry.Key), displayValue)
		count++
	}

	if count == 0 {
		if len(args) > 0 {
			fmt.Printf("%s No scope keys matching %q\n", terminal.WarnPrefix(), args[0])
		} else {
			fmt.Printf("%s No scope configuration found\n", terminal.WarnPrefix())
		}
		return nil
	}

	fmt.Println()
	fmt.Printf("%s Config file: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ConfigFilePath()))

	return nil
}

// scopeComponentColor returns a color function based on the scope component name.
func scopeComponentColor(key string) func(string) string {
	// key is like "scope.host.include" — extract the component (second segment)
	parts := strings.SplitN(key, ".", 3)
	component := ""
	if len(parts) >= 2 {
		component = parts[1]
	}

	switch component {
	case "host":
		return terminal.Cyan
	case "path":
		return terminal.Blue
	case "status_code":
		return terminal.Yellow
	case "request_content_type":
		return terminal.Magenta
	case "response_content_type":
		return terminal.Green
	case "request_string":
		return terminal.HiBlue
	case "response_string":
		return terminal.HiMagenta
	default:
		return terminal.HiGreen
	}
}
