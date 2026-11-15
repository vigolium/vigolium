package configcmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/config/yamledit"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

func newGetCmd(deps Deps) *cobra.Command {
	var showSecrets bool
	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Print one configuration value",
		Long: "Print the effective value of one dot-notation key (e.g. scope.host.include). A key that names a section " +
			"prints every key under it. Sensitive values are redacted unless --show-secrets. An unknown key is exit 2 " +
			"with the nearest known key.",
		Example: "  vigolium config get scanning_pace.rate_limit\n  vigolium config get scope.host -j",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigGet(cmd, deps, args[0], showSecrets)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "Reveal a sensitive value in plaintext instead of [redacted]; prints a warning to stderr")
	return cmd
}

func runConfigGet(cmd *cobra.Command, deps Deps, key string, showSecrets bool) error {
	settings, projectUUID, err := deps.loadSettings()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	var flagKeys []string
	if deps.FlagKeys != nil {
		flagKeys = deps.FlagKeys()
	}
	sources, err := config.TraceSources(config.TraceOptions{ConfigPath: deps.ConfigFlag(), ProjectUUID: projectUUID, FlagKeys: flagKeys})
	if err != nil {
		return fmt.Errorf("failed to trace config sources: %w", err)
	}
	key = strings.TrimSpace(key)
	entries := config.SettingEntries(settings)

	var matched []EntryView
	for _, e := range entries {
		if e.Key == key {
			matched = []EntryView{newConfigEntryView(e, config.SourceOf(sources, e.Key), showSecrets)}
			break
		}
		if strings.HasPrefix(e.Key, key+".") {
			matched = append(matched, newConfigEntryView(e, config.SourceOf(sources, e.Key), showSecrets))
		}
	}
	if len(matched) == 0 {
		return unknownConfigKeyError(key, settingKeys(entries))
	}
	if showSecrets {
		fmt.Fprintf(os.Stderr, "%s Revealing sensitive configuration values in plaintext.\n", terminal.WarningSymbol())
	}
	if deps.jsonRequested() {
		return deps.WriteJSON(cmd, "", matched, len(matched), map[string]any{
			"config_path": config.ContractPath(clicommon.EffectiveConfigPath(deps.ConfigFlag())),
			"redacted":    !showSecrets,
		})
	}
	if len(matched) == 1 && matched[0].Key == key {
		fmt.Println(matched[0].display())
		return nil
	}
	for _, e := range matched {
		fmt.Printf("%s = %s\n", e.Key, e.display())
	}
	return nil
}

// unknownConfigKeyError is a usage error naming the nearest known key.
func unknownConfigKeyError(key string, keys []string) error {
	return clicommon.CLIError{
		Err:        fmt.Errorf("unknown config key %q", key),
		Hint:       "list the keys with: vigolium config ls",
		DidYouMean: textutil.Closest(strings.ToLower(key), keys),
	}
}

func newUnsetCmd(deps Deps) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "unset <key>",
		Short: "Remove a key from the config file so its default applies",
		Long: "Delete one dot-notation key from the config file, so the built-in default (or a section default) applies " +
			"again. The file is edited in place: other keys, comments and ${VAR} placeholders are kept. A key the file " +
			"does not set is a no-op (changed false). An unknown key is exit 2.",
		Example: "  vigolium config unset scanning_pace.rate_limit\n  vigolium config unset scope.host.exclude --dry-run -j",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigUnset(cmd, deps, args[0], dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report whether the file sets the key, without editing it")
	return cmd
}

// UnsetResult is the `config unset -j` row.
type UnsetResult struct {
	Key        string `json:"key"`
	Removed    bool   `json:"removed"`
	ConfigPath string `json:"config_path"`
}

func runConfigUnset(cmd *cobra.Command, deps Deps, key string, dryRun bool) error {
	key = strings.TrimSpace(key)
	configPath := clicommon.EffectiveConfigPath(deps.ConfigFlag())
	settings, err := config.LoadSettings(deps.ConfigFlag())
	if err != nil {
		return fmt.Errorf("failed to load config, refusing to write: %w", err)
	}
	if _, ok := config.SettingDisplay(settings, key); !ok {
		return unknownConfigKeyError(key, settingKeys(config.SettingEntries(settings)))
	}
	path := strings.Split(key, ".")
	present := false
	if data, readErr := os.ReadFile(config.ExpandPath(configPath)); readErr == nil {
		if doc, parseErr := yamledit.Parse(data); parseErr == nil && doc.Get(path) != nil {
			present = true
		}
	}
	changed := false
	if present && !dryRun {
		changed, err = config.EditConfigFile(configPath, func(d *yamledit.Doc) error {
			_, delErr := d.Delete(path)
			return delErr
		})
		if err != nil {
			if errors.Is(err, config.ErrInvalidValue) {
				return clicommon.CLIError{Err: fmt.Errorf("unset %q: %w", key, err), Code: apicontract.CodeConfigInvalid}
			}
			return fmt.Errorf("failed to save config: %w", err)
		}
	}
	action := "delete"
	if !present {
		action = "noop"
	}
	row := []UnsetResult{{Key: key, Removed: present, ConfigPath: config.ContractPath(configPath)}}
	if deps.mutationJSONRequested() {
		if dryRun && deps.WriteDryRunMutation != nil {
			return deps.WriteDryRunMutation(cmd, row, action, nil)
		}
		return deps.WriteMutation(cmd, row, changed, action, nil)
	}
	switch {
	case !present:
		fmt.Printf("%s %s is not set in %s; its default already applies\n", terminal.InfoSymbol(), key, config.ContractPath(configPath))
	case dryRun:
		fmt.Printf("%s Dry run: would remove %s from %s\n", terminal.InfoSymbol(), key, config.ContractPath(configPath))
	default:
		fmt.Printf("%s Removed %s from %s; the default applies\n", terminal.SuccessSymbol(), key, config.ContractPath(configPath))
	}
	return nil
}

// settingKeys lists the keys of entries, for near-miss suggestions.
func settingKeys(entries []config.SettingEntry) []string {
	keys := make([]string, len(entries))
	for i, e := range entries {
		keys[i] = e.Key
	}
	return keys
}
