package config

// DynamicAssessmentConfig groups configuration for the dynamic assessment
// scan phase: which modules are enabled and JS extension settings.
type DynamicAssessmentConfig struct {
	EnabledModules EnabledModulesConfig `yaml:"enabled_modules"`
	Extensions     ExtensionsConfig     `yaml:"extensions"`
}

// DefaultDynamicAssessmentConfig returns defaults with all modules enabled
// and extensions disabled.
func DefaultDynamicAssessmentConfig() *DynamicAssessmentConfig {
	return &DynamicAssessmentConfig{
		EnabledModules: *DefaultEnabledModulesConfig(),
		Extensions:     *DefaultExtensionsConfig(),
	}
}
