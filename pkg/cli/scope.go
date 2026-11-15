package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var scopeCmd = &cobra.Command{
	Use:     "scope",
	Aliases: []string{"sc"},
	Short:   "Manage scan scope rules",
	Long:    "Inspect and edit scope rules that control which hosts, paths, status codes, and content types are in-scope for scanning. Running 'vigolium scope' without a subcommand is equivalent to 'scope view'.",
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScopeView(scopeViewCmd, args)
	},
}

var scopeViewCmd = &cobra.Command{
	Use:     "view [component]",
	Aliases: []string{"ls", "list"},
	Short:   "Display current scope configuration",
	Long:    "Print all scope.* config entries. Pass a component name (host, path, status_code, request_content_type, response_content_type, request_string, response_string) to filter to that subset.",
	Args:    cobra.MaximumNArgs(1),
	RunE:    runScopeView,
}

func init() {
	rootCmd.AddCommand(scopeCmd)
	scopeCmd.AddCommand(scopeViewCmd)
}

// scopeEntry is one scope.* setting, in the shape a machine consumer reads.
// `component` is split out because it is the axis the whole command is organized
// around and deriving it from the key means every consumer reimplements the
// same string split.
type scopeEntry struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Component string `json:"component"`
	Empty     bool   `json:"empty"`
}

func runScopeView(cmd *cobra.Command, args []string) error {
	settings, err := clicommon.LoadSettings(globalConfig)
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

	matched := make([]scopeEntry, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Key), filter) {
			continue
		}
		matched = append(matched, scopeEntry{
			Key:       entry.Key,
			Value:     entry.Value,
			Component: scopeComponentOf(entry.Key),
			Empty:     entry.Value == "" || entry.Value == "<nil>",
		})
	}

	// A component filter that names no scope key is a typo (`scope hosts`), not
	// an empty scope: answering with zero rows and exit 0 read as "no rules".
	if len(args) > 0 && len(matched) == 0 {
		return unknownScopeComponentError(args[0], entries)
	}

	// -j used to be accepted here and produce ANSI-colored prose on stdout with
	// exit 0 — the worst combination available, because a consumer parsing it
	// fails for a reason the exit code says nothing about. An empty result is an
	// empty array, never a warning line.
	if globalJSON {
		env := newMachineEnvelope(cmd, kindRead, "entries", matched, int64(len(matched)), 0, len(matched))
		env.With("config_path", config.ContractPath(effectiveConfigPath()))
		if len(args) > 0 {
			env.With("component_filter", args[0])
		}
		return writeAgentJSON(env)
	}

	for _, e := range matched {
		displayValue := e.Value
		if e.Empty {
			displayValue = "(empty)"
		}
		fmt.Printf("  %s = %s\n", scopeComponentColor(e.Key)(e.Key), displayValue)
	}

	if len(matched) == 0 {
		if len(args) > 0 {
			fmt.Printf("%s No scope keys matching %q\n", terminal.WarnPrefix(), args[0])
		} else {
			fmt.Printf("%s No scope configuration found\n", terminal.WarnPrefix())
		}
		return nil
	}

	fmt.Println()
	fmt.Printf("%s Config file: %s\n", terminal.InfoSymbol(), terminal.Gray(config.ContractPath(effectiveConfigPath())))

	return nil
}

// scopeComponentOf extracts the component segment from a key like
// "scope.host.include".
func scopeComponentOf(key string) string {
	parts := strings.SplitN(key, ".", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// scopeComponentColor returns a color function based on the scope component name.
func scopeComponentColor(key string) func(string) string {
	switch scopeComponentOf(key) {
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

// unknownScopeComponentError is the usage error for a component filter that
// matches no scope.* key, naming the components that exist.
func unknownScopeComponentError(typed string, entries []config.ConfigEntry) error {
	seen := map[string]bool{}
	var components []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Key, "scope.") {
			continue
		}
		if c := scopeComponentOf(e.Key); c != "" && !seen[c] {
			seen[c] = true
			components = append(components, c)
		}
	}
	sort.Strings(components)
	component, _, _ := strings.Cut(strings.ToLower(typed), ".")
	return clicommon.CLIError{
		Err:        fmt.Errorf("no scope component %q; components: %s", typed, strings.Join(components, ", ")),
		DidYouMean: closestName(component, components),
		UsageArgv:  clicommon.UsageArgvFor("scope view"),
	}
}
