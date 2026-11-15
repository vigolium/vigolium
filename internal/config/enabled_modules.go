package config

import "slices"

// EnabledModulesConfig controls which scanner modules are active.
//
// The allow-lists select: ["all"] (the default) enables every registered
// module, including ones a later release adds; a list of module IDs runs only
// those. An empty allow-list is a configuration error (it used to mean "all",
// which made a list emptied by hand silently re-enable everything).
//
// The deny-lists subtract from whatever the allow-lists select. `module
// disable` writes them, so turning one module off keeps the default ["all"]
// and modules added by later releases stay on.
type EnabledModulesConfig struct {
	ActiveModules          []string `yaml:"active_modules"`
	PassiveModules         []string `yaml:"passive_modules"`
	DisabledActiveModules  []string `yaml:"disabled_active_modules,omitempty"`
	DisabledPassiveModules []string `yaml:"disabled_passive_modules,omitempty"`
}

// DefaultEnabledModulesConfig returns the default config where all modules are enabled.
func DefaultEnabledModulesConfig() *EnabledModulesConfig {
	return &EnabledModulesConfig{
		ActiveModules:  []string{"all"},
		PassiveModules: []string{"all"},
	}
}

// AllowsAll reports whether an allow-list selects every module.
func AllowsAll(list []string) bool {
	return len(list) == 0 || (len(list) == 1 && list[0] == "all")
}

// ActiveEnabled reports whether the active module id is enabled: selected by
// the allow-list and not on the deny-list.
func (c *EnabledModulesConfig) ActiveEnabled(id string) bool {
	return moduleEnabled(id, c.ActiveModules, c.DisabledActiveModules)
}

// PassiveEnabled is ActiveEnabled for passive modules.
func (c *EnabledModulesConfig) PassiveEnabled(id string) bool {
	return moduleEnabled(id, c.PassiveModules, c.DisabledPassiveModules)
}

func moduleEnabled(id string, allow, deny []string) bool {
	if slices.Contains(deny, id) {
		return false
	}
	return AllowsAll(allow) || slices.Contains(allow, id)
}
