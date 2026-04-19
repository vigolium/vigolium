package config

// DynamicAssessmentConfig holds settings for the dynamic-assessment scan phase:
// enabled modules and JS extensions.
type DynamicAssessmentConfig struct {
	MaxFeedbackRounds int                  `yaml:"max_feedback_rounds"`
	EnabledModules    EnabledModulesConfig `yaml:"enabled_modules"`
	Extensions        ExtensionsConfig     `yaml:"extensions"`
}

func DefaultDynamicAssessmentConfig() *DynamicAssessmentConfig {
	return &DynamicAssessmentConfig{
		MaxFeedbackRounds: 1,
		EnabledModules:    *DefaultEnabledModulesConfig(),
		Extensions:        *DefaultExtensionsConfig(),
	}
}
