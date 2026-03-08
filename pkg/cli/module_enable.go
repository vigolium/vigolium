package cli

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
)

var moduleExactID bool

var moduleEnableCmd = &cobra.Command{
	Use:     "enable <search>",
	Aliases: []string{"e"},
	Short:   "Enable modules matching a search term",
	Args:    cobra.ExactArgs(1),
	RunE:    runModuleEnable,
}

var moduleDisableCmd = &cobra.Command{
	Use:     "disable <search>",
	Aliases: []string{"d"},
	Short:   "Disable modules matching a search term",
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

// addModuleToList adds a module ID to the config list.
// If list is ["all"], returns it unchanged (already enabled).
// Returns the updated list and whether it was modified.
func addModuleToList(list []string, moduleID string) ([]string, bool) {
	if len(list) == 1 && list[0] == "all" {
		return list, false
	}
	for _, id := range list {
		if id == moduleID {
			return list, false
		}
	}
	return append(list, moduleID), true
}

// removeModuleFromList removes a module ID from the config list.
// If list is ["all"], expands it to all IDs of that type minus the target.
func removeModuleFromList(list []string, moduleID string, moduleType string) ([]string, bool) {
	if len(list) == 1 && list[0] == "all" {
		expanded := expandAllModuleIDs(moduleType)
		var result []string
		for _, id := range expanded {
			if id != moduleID {
				result = append(result, id)
			}
		}
		return result, true
	}

	var result []string
	found := false
	for _, id := range list {
		if id == moduleID {
			found = true
		} else {
			result = append(result, id)
		}
	}
	return result, found
}

// expandAllModuleIDs returns all module IDs for the given type ("active" or "passive").
func expandAllModuleIDs(moduleType string) []string {
	if moduleType == "active" {
		return modules.GetActiveModulesID()
	}
	return modules.GetPassiveModulesID()
}

func runModuleEnable(cmd *cobra.Command, args []string) error {
	search := args[0]
	matches := findMatchingModules(search, moduleExactID)

	if len(matches) == 0 {
		fmt.Printf("%s No modules matching %q\n", terminal.WarnPrefix(), search)
		return nil
	}

	configPath := config.ConfigFilePath()
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	var enabled []string
	for _, m := range matches {
		var modified bool
		if m.moduleType == "active" {
			settings.DynamicAssessment.EnabledModules.ActiveModules, modified = addModuleToList(settings.DynamicAssessment.EnabledModules.ActiveModules, m.id)
		} else {
			settings.DynamicAssessment.EnabledModules.PassiveModules, modified = addModuleToList(settings.DynamicAssessment.EnabledModules.PassiveModules, m.id)
		}
		if modified {
			enabled = append(enabled, m.id)
		}
	}

	if len(enabled) == 0 {
		fmt.Printf("%s All matching modules are already enabled\n", terminal.InfoSymbol())
		return nil
	}

	if err := config.SaveSettings(configPath, settings); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("%s Enabled %d module(s):\n", terminal.SuccessSymbol(), len(enabled))
	for _, id := range enabled {
		fmt.Printf("  %s %s\n", terminal.SuccessSymbol(), terminal.Cyan(id))
	}
	fmt.Printf("\n%s Config saved to %s\n", terminal.InfoSymbol(), terminal.Gray(configPath))
	return nil
}

func runModuleDisable(cmd *cobra.Command, args []string) error {
	search := args[0]
	matches := findMatchingModules(search, moduleExactID)

	if len(matches) == 0 {
		fmt.Printf("%s No modules matching %q\n", terminal.WarnPrefix(), search)
		return nil
	}

	configPath := config.ConfigFilePath()
	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	var disabled []string
	for _, m := range matches {
		var modified bool
		if m.moduleType == "active" {
			settings.DynamicAssessment.EnabledModules.ActiveModules, modified = removeModuleFromList(
				settings.DynamicAssessment.EnabledModules.ActiveModules, m.id, m.moduleType)
		} else {
			settings.DynamicAssessment.EnabledModules.PassiveModules, modified = removeModuleFromList(
				settings.DynamicAssessment.EnabledModules.PassiveModules, m.id, m.moduleType)
		}
		if modified {
			disabled = append(disabled, m.id)
		}
	}

	if len(disabled) == 0 {
		fmt.Printf("%s All matching modules are already disabled\n", terminal.InfoSymbol())
		return nil
	}

	if err := config.SaveSettings(configPath, settings); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("%s Disabled %d module(s):\n", terminal.SuccessSymbol(), len(disabled))
	for _, id := range disabled {
		fmt.Printf("  %s %s\n", terminal.WarnPrefix(), terminal.Yellow(id))
	}
	fmt.Printf("\n%s Config saved to %s\n", terminal.InfoSymbol(), terminal.Gray(configPath))

	// Hint: show how to re-enable
	if len(disabled) == 1 {
		fmt.Printf("%s Re-enable with: %s\n", terminal.InfoSymbol(),
			terminal.Gray("vigolium module enable "+disabled[0]+" --id"))
	} else {
		fmt.Printf("%s Re-enable with: %s\n", terminal.InfoSymbol(),
			terminal.Gray(fmt.Sprintf("vigolium module enable %s", strings.ToLower(search))))
	}
	return nil
}
