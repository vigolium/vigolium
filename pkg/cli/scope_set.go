package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var scopeSetProject string

var scopeSetCmd = &cobra.Command{
	Use:   "set <component.field> <value>",
	Short: "Set a scope rule",
	Long: "Set a scope rule using component.field notation (e.g. host.exclude \"*.internal.com,admin.*\").\n\n" +
		"Lists take the comma form or JSON/YAML flow syntax ('[\"*.example.com\",\"example.com\"]'); '<rule>.add <value>' " +
		"appends and '<rule>.clear' (no value) empties. The value is checked with the same rules as 'config validate' and refused " +
		"(exit 2, nothing written) when it would break the scope. Writes the global config, or with --project the " +
		"project's overlay (~/.vigolium/projects/<uuid>/config.yaml). The file is edited in place, keeping its comments " +
		"and ${VAR} placeholders. A config that fails to load is never overwritten.",
	Args: cobra.RangeArgs(1, 2),
	RunE: runScopeSet,
}

func init() {
	scopeSetCmd.Flags().StringVar(&scopeSetProject, "project", "", "Write the rule to this project's config overlay instead of the global config (an existing project: UUID, name or unique 8+ char UUID prefix)")
	scopeCmd.AddCommand(scopeSetCmd)
}

func runScopeSet(cmd *cobra.Command, args []string) error {
	// An overlay is written only for a project that exists: writing one for a
	// typo created ~/.vigolium/projects/<typo>/ that no scan would ever read.
	if scopeSetProject != "" {
		resolved, err := resolveProjectRefArg(cmd.Context(), scopeSetProject)
		if err != nil {
			return err
		}
		scopeSetProject = resolved
	}

	key := "scope." + args[0]
	var value string
	switch {
	case len(args) == 2:
		value = args[1]
	case !strings.HasSuffix(key, ".clear"):
		return usageErrorf("scope set %s needs a value (only '<rule>.clear' takes none)", args[0])
	}

	// config.LoadSettings*, not clicommon.LoadSettings: the CLI loader answers a
	// discovered-but-unreadable config with built-in defaults, and saving those
	// back would replace the operator's file with them. Refuse instead.
	settings, err := config.LoadSettingsWithProject(globalConfig, scopeSetProject)
	if err != nil {
		return fmt.Errorf("failed to load config, refusing to write: %w", err)
	}

	// The rule's value before the write, for the -j old/new pair. A list-op key
	// (`.add`/`.clear`) reports the list it changes.
	ruleKey := strings.TrimSuffix(strings.TrimSuffix(key, ".add"), ".clear")
	oldValue := flatSettingValue(settings, ruleKey)

	edit, err := config.SetFieldEdit(settings, key, value)
	if err != nil {
		if errors.Is(err, config.ErrUnknownKey) || errors.Is(err, config.ErrInvalidValue) {
			return clicommon.AsUsageError(fmt.Errorf("failed to set %q: %w", key, err))
		}
		return fmt.Errorf("failed to set %q: %w", key, err)
	}

	where := ""
	layer, configPath := "global", effectiveConfigPath()
	if scopeSetProject != "" {
		path, err := config.SetProjectOverlayEdit(scopeSetProject, key, edit)
		if err != nil {
			if errors.Is(err, config.ErrUnknownKey) || errors.Is(err, config.ErrInvalidValue) {
				return clicommon.AsUsageError(err)
			}
			return fmt.Errorf("failed to save project config: %w", err)
		}
		where = " (" + config.ContractPath(path) + ")"
		layer, configPath = "project", path
	} else if _, err := config.EditConfigFile(configPath, edit); err != nil {
		if errors.Is(err, config.ErrInvalidValue) {
			return clicommon.AsUsageError(fmt.Errorf("failed to set %q: %w", key, err))
		}
		return fmt.Errorf("failed to save config: %w", err)
	}

	if globalJSON {
		newValue := flatSettingValue(settings, ruleKey)
		changed := oldValue != newValue
		action := "update"
		if !changed {
			action = "noop"
		}
		opts := []envOpt{}
		if scopeSetProject != "" {
			opts = append(opts, withProjectUUID(scopeSetProject))
		}
		return emitMutation(cmd, "", mutationResult{
			Changed: changed,
			Action:  action,
			Items: []scopeSetView{{
				Key: ruleKey, Old: oldValue, New: newValue,
				Layer: layer, ConfigPath: config.ContractPath(configPath),
			}},
		}, opts...)
	}

	fmt.Printf("%s Set %s = %s%s\n", terminal.SuccessSymbol(), terminal.Cyan(key), value, terminal.Gray(where))
	return nil
}

// scopeSetView is the `scope set -j` row: the rule, its value before and after
// (in `config ls` rendering), and which config layer was written.
type scopeSetView struct {
	Key        string `json:"key"`
	Old        string `json:"old"`
	New        string `json:"new"`
	Layer      string `json:"layer"`
	ConfigPath string `json:"config_path"`
}

// flatSettingValue renders one setting the way `config ls` does, or "" when the
// key is unset.
func flatSettingValue(settings *config.Settings, key string) string {
	for _, e := range config.FlattenSettings(settings) {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}
