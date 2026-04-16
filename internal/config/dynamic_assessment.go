package config

// DynamicAssessmentConfig holds settings for the dynamic-assessment scan phase:
// enabled modules and JS extensions.
type DynamicAssessmentConfig struct {
	EnabledModules EnabledModulesConfig `yaml:"enabled_modules"`
	Extensions     ExtensionsConfig     `yaml:"extensions"`
}

func DefaultDynamicAssessmentConfig() *DynamicAssessmentConfig {
	return &DynamicAssessmentConfig{
		EnabledModules: *DefaultEnabledModulesConfig(),
		Extensions:     *DefaultExtensionsConfig(),
	}
}
