package config

// AuditConfig groups configuration for the audit scan phase:
// which modules are enabled and JS extension settings.
type AuditConfig struct {
	EnabledModules EnabledModulesConfig `yaml:"enabled_modules"`
	Extensions     ExtensionsConfig     `yaml:"extensions"`
}

// DefaultAuditConfig returns defaults with all modules enabled
// and extensions disabled.
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		EnabledModules: *DefaultEnabledModulesConfig(),
		Extensions:     *DefaultExtensionsConfig(),
	}
}
