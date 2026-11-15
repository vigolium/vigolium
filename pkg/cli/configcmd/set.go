package configcmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

func newSetCmd(deps Deps, example string) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value",
		Long: "Set a configuration value using dot-notation key (e.g. notify.enabled true).\nAlso accepts 'key = value' and 'key=value' formats.\n\n" +
			"List and map values take JSON or YAML flow syntax ('[\"a.example\",\"b.example\"]', '[a, b]', '{\"k\":\"v\"}'),\n" +
			"checked against the setting's type; the comma form (a,b) still works for lists. '<list>.add <value>' appends\n" +
			"one element or a JSON list; '<list>.clear' (no value) empties it. Booleans take true/false (or 1/0, t/f) and\n" +
			"integers must parse exactly. A value that fails validation (see 'config validate') is refused with exit 2\n" +
			"and the file is left unchanged. The file is edited in place: comments and ${VAR} placeholders are kept.\n" +
			"The confirmation shows the value read back from the file.",
		Args:    cobra.RangeArgs(1, 3),
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigSet(cmd, deps, args, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show the value the key would get, without editing the config file")
	return cmd
}

func runConfigSet(cmd *cobra.Command, deps Deps, args []string, dryRun bool) error {
	var key, value string
	switch {
	case len(args) == 1 && strings.Contains(args[0], "="):
		// Support "key=value" format (single argument)
		k, v, _ := strings.Cut(args[0], "=")
		key = strings.TrimSpace(k)
		value = strings.TrimSpace(v)
		if key == "" {
			return clicommon.UsageErrorf("usage: config set <key>=<value>")
		}
	case len(args) == 3 && args[1] == "=":
		// Support "key = value" format (copied from config ls output)
		key = args[0]
		value = args[2]
	case len(args) == 2:
		key = args[0]
		value = args[1]
	case len(args) == 1 && strings.HasSuffix(args[0], ".clear"):
		// `<list>.clear` takes no value.
		key = args[0]
	default:
		return clicommon.UsageErrorf("usage: config set <key> <value> | config set <key>=<value> | config set <key> = <value>")
	}

	// The loaded settings validate and parse the value; the file itself is
	// edited in place on its raw text, so `${VAR}` placeholders and comments
	// survive and no expanded secret is ever written back.
	configPath := clicommon.EffectiveConfigPath(deps.ConfigFlag())
	settings, err := config.LoadSettings(deps.ConfigFlag())
	if err != nil {
		return fmt.Errorf("failed to load config, refusing to write: %w", err)
	}

	settingKey := config.SettingPath(key)
	before, _ := config.SettingDisplay(settings, settingKey)
	edit, err := config.SetFieldEdit(settings, key, value)
	if err != nil {
		// A key that names no setting, or a value that cannot be stored under
		// it (a list that does not parse, a bool that is not true/false, a
		// scope pattern that validation rejects), is a mistake on the command
		// line (exit 2), not a failure to write the config. Nothing was written.
		if errors.Is(err, config.ErrUnknownKey) || errors.Is(err, config.ErrInvalidValue) {
			return clicommon.AsUsageError(fmt.Errorf("failed to set %q: %w", key, err))
		}
		return fmt.Errorf("failed to set %q: %w", key, err)
	}
	if dryRun {
		return reportConfigSetDryRun(cmd, deps, settings, key, settingKey, value, before, configPath)
	}
	changed, err := config.EditConfigFile(configPath, edit)
	if err != nil {
		if errors.Is(err, config.ErrInvalidValue) {
			return clicommon.AsUsageError(fmt.Errorf("failed to set %q: %w", key, err))
		}
		return fmt.Errorf("failed to save config: %w", err)
	}

	// Echo what the file now holds, read back through the loader, rather than
	// the argument: the two differ whenever the value was normalized.
	stored := value
	if reloaded, err := config.LoadSettings(configPath); err == nil {
		if v, ok := config.SettingDisplay(reloaded, settingKey); ok {
			stored = v
		}
	}

	// The confirmation used to echo the supplied value verbatim, so
	// `config set agent.api_key sk-...` printed the key straight back to stdout
	// — into the shell history, the CI log, and the agent transcript. `config ls`
	// redacts the same value; the write path has to agree with the read path.
	sensitive := config.IsSensitiveEntry(settingKey, value) || config.IsSensitiveEntry(settingKey, stored)
	shown := stored
	if sensitive {
		shown = clicommon.SecretPlaceholder
	}

	if deps.mutationJSONRequested() {
		action := "update"
		if !changed {
			action = "noop"
		}
		return deps.WriteMutation(cmd, []configSetResult{{
			Key:        key,
			Value:      shown,
			Sensitive:  sensitive,
			Redacted:   sensitive,
			ConfigPath: config.ContractPath(configPath),
		}}, changed, action, nil)
	}

	fmt.Printf("%s Set %s = %s\n", terminal.SuccessSymbol(), terminal.Cyan(settingKey), shown)
	return nil
}

// configSetResult is the machine shape of a completed write.
type configSetResult struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	Sensitive  bool   `json:"sensitive"`
	Redacted   bool   `json:"redacted"`
	ConfigPath string `json:"config_path"`
}

// reportConfigSetDryRun reports the value a key would get (the in-memory
// settings already hold it) without touching the file.
func reportConfigSetDryRun(cmd *cobra.Command, deps Deps, settings *config.Settings, key, settingKey, value, before, configPath string) error {
	after, ok := config.SettingDisplay(settings, settingKey)
	if !ok {
		after = value
	}
	sensitive := config.IsSensitiveEntry(settingKey, value) || config.IsSensitiveEntry(settingKey, after)
	shown := after
	if sensitive {
		shown = clicommon.SecretPlaceholder
	}
	action := "update"
	if before == after {
		action = "noop"
	}
	if deps.mutationJSONRequested() && deps.WriteDryRunMutation != nil {
		return deps.WriteDryRunMutation(cmd, []configSetResult{{
			Key:        key,
			Value:      shown,
			Sensitive:  sensitive,
			Redacted:   sensitive,
			ConfigPath: config.ContractPath(configPath),
		}}, action, nil)
	}
	fmt.Printf("%s Dry run: would set %s = %s in %s\n", terminal.InfoSymbol(), terminal.Cyan(settingKey), shown, config.ContractPath(configPath))
	return nil
}
