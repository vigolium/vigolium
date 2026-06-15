package config

// DynamicAssessmentConfig holds settings for the dynamic-assessment scan phase:
// enabled modules and JS extensions.
type DynamicAssessmentConfig struct {
	MaxFeedbackRounds int                  `yaml:"max_feedback_rounds"`
	EnabledModules    EnabledModulesConfig `yaml:"enabled_modules"`
	Extensions        ExtensionsConfig     `yaml:"extensions"`

	// MaxParamShapeSamples caps how many value-distinct samples of the same
	// param shape (host + path + method + query/form/JSON param-name-set) are
	// scanned in the dynamic-assessment phase. It collapses redundant fan-out over
	// requests that differ only in param values (e.g. /search?q=1..N, or repeated
	// same-shape form/JSON POSTs) without touching stored records; a request whose
	// body shape can't be seen (unseen or multipart body) is never coalesced.
	// Following the MaxFeedbackRounds convention, 0 (or unset, including
	// when a scanning profile overlays this section) means "use the built-in
	// default" (database.DefaultMaxParamShapeSamples); a negative value disables
	// coalescing entirely.
	MaxParamShapeSamples int `yaml:"max_param_shape_samples"`
}

func DefaultDynamicAssessmentConfig() *DynamicAssessmentConfig {
	return &DynamicAssessmentConfig{
		MaxFeedbackRounds:    1,
		EnabledModules:       *DefaultEnabledModulesConfig(),
		Extensions:           *DefaultExtensionsConfig(),
		MaxParamShapeSamples: 3,
	}
}
