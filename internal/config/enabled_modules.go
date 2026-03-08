package config

// EnabledModulesConfig controls which scanner modules are active.
// Use ["all"] (the default) to enable every registered module,
// or list specific module IDs to run only those.
type EnabledModulesConfig struct {
	ActiveModules  []string `yaml:"active_modules"`
	PassiveModules []string `yaml:"passive_modules"`
}

// DefaultEnabledModulesConfig returns the default config where all modules are enabled.
func DefaultEnabledModulesConfig() *EnabledModulesConfig {
	return &EnabledModulesConfig{
		ActiveModules:  []string{"all"},
		PassiveModules: []string{"all"},
	}
}
