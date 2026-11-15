package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/config/yamledit"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"gopkg.in/yaml.v3"
)

var moduleExactID bool

var moduleEnableCmd = &cobra.Command{
	Use:     "enable <search>",
	Aliases: []string{"e"},
	Short:   "Enable modules matching a search term",
	Long:    "Enable every module whose ID, name, description, or tag matches the search term and persist the change to the config file: the module leaves the disabled_*_modules deny-list, and joins an explicit allow-list. A term matching more than 5 modules needs --force. Pass --id to require an exact module-ID match instead of fuzzy matching.",
	Args:    cobra.ExactArgs(1),
	RunE:    runModuleEnable,
}

var moduleDisableCmd = &cobra.Command{
	Use:     "disable <search>",
	Aliases: []string{"d"},
	Short:   "Disable modules matching a search term",
	Long:    "Disable every module whose ID, name, description, or tag matches the search term and persist the change to the config file by adding it to the disabled_active_modules / disabled_passive_modules deny-list (the [all] allow-list stays, so modules added by later releases stay on). A term matching more than 5 modules needs --force. Pass --id to require an exact module-ID match instead of fuzzy matching.",
	Args:    cobra.ExactArgs(1),
	RunE:    runModuleDisable,
}

func init() {
	moduleCmd.AddCommand(moduleEnableCmd)
	moduleCmd.AddCommand(moduleDisableCmd)

	moduleEnableCmd.Flags().BoolVar(&moduleExactID, "id", false, "Match exact module ID instead of fuzzy search")
	moduleDisableCmd.Flags().BoolVar(&moduleExactID, "id", false, "Match exact module ID instead of fuzzy search")
}

type matchedModule struct {
	id         string
	moduleType string // "active" or "passive"
}

// findMatchingModules returns modules matching the search term.
// If exactID is true, matches by exact module ID; otherwise uses fuzzy matching.
func findMatchingModules(search string, exactID bool) []matchedModule {
	var matches []matchedModule

	for _, m := range modules.GetActiveModules() {
		if exactID {
			if m.ID() == search {
				matches = append(matches, matchedModule{id: m.ID(), moduleType: "active"})
			}
		} else {
			if moduleMatchesFilter(m, search) {
				matches = append(matches, matchedModule{id: m.ID(), moduleType: "active"})
			}
		}
	}

	for _, m := range modules.GetPassiveModules() {
		if exactID {
			if m.ID() == search {
				matches = append(matches, matchedModule{id: m.ID(), moduleType: "passive"})
			}
		} else {
			if moduleMatchesFilter(m, search) {
				matches = append(matches, matchedModule{id: m.ID(), moduleType: "passive"})
			}
		}
	}

	return matches
}

// maxModuleToggleWithoutForce is how many modules one enable/disable may flip
// without --force. A fuzzy term like "a" matches hundreds.
const maxModuleToggleWithoutForce = 5

// checkModuleToggleBreadth refuses a search that matched more modules than a
// typo should be able to flip, unless --force.
func checkModuleToggleBreadth(verb, search string, matches []matchedModule) error {
	if len(matches) <= maxModuleToggleWithoutForce || globalForce {
		return nil
	}
	return usageErrorf("%q matches %d modules; pass --force to %s all of them, or --id with an exact module ID (list them with `vigolium module ls %s`)",
		search, len(matches), verb, search)
}

const enabledModulesKey = "dynamic-assessment.enabled_modules."

// moduleListKeys returns the allow-list and deny-list config keys for a module type.
func moduleListKeys(moduleType string) (allow, deny string) {
	if moduleType == "active" {
		return enabledModulesKey + "active_modules", enabledModulesKey + "disabled_active_modules"
	}
	return enabledModulesKey + "passive_modules", enabledModulesKey + "disabled_passive_modules"
}

func moduleEnabledIn(em *config.EnabledModulesConfig, m matchedModule) bool {
	if m.moduleType == "active" {
		return em.ActiveEnabled(m.id)
	}
	return em.PassiveEnabled(m.id)
}

// toggleModules flips each match to the requested state in the raw config and
// returns the ids it changed. Disabling appends to the deny-list, so the
// allow-list keeps selecting modules a later release adds. Enabling removes
// from the deny-list, and adds to the allow-list only when that list is an
// explicit one that does not hold the module.
func toggleModules(configPath string, em *config.EnabledModulesConfig, matches []matchedModule, enable bool) ([]string, error) {
	var flipped []string
	add := map[string][]*yaml.Node{}
	remove := map[string][]string{}
	for _, m := range matches {
		if moduleEnabledIn(em, m) == enable {
			continue
		}
		flipped = append(flipped, m.id)
		allowKey, denyKey := moduleListKeys(m.moduleType)
		allow := em.PassiveModules
		if m.moduleType == "active" {
			allow = em.ActiveModules
		}
		node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: m.id}
		if !enable {
			add[denyKey] = append(add[denyKey], node)
			continue
		}
		remove[denyKey] = append(remove[denyKey], m.id)
		if !config.AllowsAll(allow) && !slices.Contains(allow, m.id) {
			add[allowKey] = append(add[allowKey], node)
		}
	}
	if len(flipped) == 0 || moduleToggleDryRun {
		return flipped, nil
	}
	_, err := config.EditConfigFile(configPath, func(d *yamledit.Doc) error {
		for _, key := range slices.Sorted(maps.Keys(remove)) {
			if _, err := d.RemoveItems(strings.Split(key, "."), remove[key]...); err != nil {
				return err
			}
		}
		for _, key := range slices.Sorted(maps.Keys(add)) {
			if _, err := d.AppendUnique(strings.Split(key, "."), add[key]...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return flipped, nil
}

// noModulesMatchError rejects a search that matched nothing. It used to print a
// warning to stdout and exit 0, so a typo'd module ID in a setup script looked
// exactly like a successful enable. It is a usage error (exit 2): nothing was
// read or written, and the fix is a different search term.
func noModulesMatchError(search string) error {
	return usageErrorf("no modules matching %q (list module IDs with `vigolium module ls`)", search)
}

func runModuleEnable(cmd *cobra.Command, args []string) error {
	return runModuleToggle(cmd, args[0], true)
}

func runModuleDisable(cmd *cobra.Command, args []string) error {
	return runModuleToggle(cmd, args[0], false)
}

func runModuleToggle(cmd *cobra.Command, search string, enable bool) error {
	verb := "disable"
	if enable {
		verb = "enable"
	}
	matches := findMatchingModules(search, moduleExactID)
	if len(matches) == 0 {
		return noModulesMatchError(search)
	}
	if err := checkModuleToggleBreadth(verb, search, matches); err != nil {
		return err
	}

	// EffectiveConfigPath, not ConfigFilePath: with --config set, this command
	// used to READ the named file and WRITE the discovered one. config.LoadSettings,
	// not the CLI loader that answers a broken config with defaults: the state
	// read here decides what is written.
	configPath := clicommon.EffectiveConfigPath(globalConfig)
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		return fmt.Errorf("failed to load config, refusing to write: %w", err)
	}
	flipped, err := toggleModules(configPath, &settings.DynamicAssessment.EnabledModules, matches, enable)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	if globalJSON {
		return emitModuleToggle(cmd, verb, matches, flipped, configPath)
	}
	if len(flipped) == 0 {
		fmt.Printf("%s All matching modules are already %sd\n", terminal.InfoSymbol(), verb)
		return nil
	}
	if moduleToggleDryRun {
		fmt.Printf("%s Dry run: would %s %d module(s) in %s: %s\n", terminal.InfoSymbol(), verb, len(flipped),
			terminal.Gray(configPath), strings.Join(flipped, ", "))
		return nil
	}
	if enable {
		fmt.Printf("%s Enabled %d module(s):\n", terminal.SuccessSymbol(), len(flipped))
		for _, id := range flipped {
			fmt.Printf("  %s %s\n", terminal.SuccessSymbol(), terminal.Cyan(id))
		}
	} else {
		fmt.Printf("%s Disabled %d module(s):\n", terminal.SuccessSymbol(), len(flipped))
		for _, id := range flipped {
			fmt.Printf("  %s %s\n", terminal.WarnPrefix(), terminal.Yellow(id))
		}
	}
	fmt.Printf("\n%s Config saved to %s\n", terminal.InfoSymbol(), terminal.Gray(configPath))
	if !enable {
		hint := "vigolium module enable " + strings.ToLower(search)
		if len(flipped) == 1 {
			hint = "vigolium module enable " + flipped[0] + " --id"
		}
		fmt.Printf("%s Re-enable with: %s\n", terminal.InfoSymbol(), terminal.Gray(hint))
	}
	return nil
}

// moduleToggleView is one matched module in `module enable/disable -j`.
type moduleToggleView struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// Changed is false for a module that was already in the requested state.
	Changed bool `json:"changed"`
}

// emitModuleToggle writes the module enable/disable result: every module the
// search matched, each saying whether this run flipped it. changed is true when
// any did (and the config was written).
func emitModuleToggle(cmd *cobra.Command, action string, matches []matchedModule, flipped []string, configPath string) error {
	flippedSet := make(map[string]bool, len(flipped))
	for _, id := range flipped {
		flippedSet[id] = true
	}
	items := make([]moduleToggleView, 0, len(matches))
	for _, m := range matches {
		items = append(items, moduleToggleView{ID: m.id, Type: m.moduleType, Changed: flippedSet[m.id]})
	}
	if len(flipped) == 0 {
		action = "noop"
	}
	return emitMutation(cmd, "", mutationResult{
		Changed: len(flipped) > 0,
		Action:  action,
		DryRun:  moduleToggleDryRun,
		Items:   items,
		Extra: map[string]any{
			"modules_changed": len(flipped),
			"config_path":     config.ContractPath(configPath),
		},
	})
}
