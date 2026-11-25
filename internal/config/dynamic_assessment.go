package config

import "strings"

// DynamicAssessmentConfig holds settings for the dynamic-assessment scan phase:
// enabled modules and JS extensions.
type DynamicAssessmentConfig struct {
	MaxFeedbackRounds int `yaml:"max_feedback_rounds"`

	// ExternalLookups lets modules query third-party services that are not
	// the scan target (dependency_confusion's npm registry lookups) through
	// the scan's proxy and timeout. Off by default: the lookups
	// disclose the target's internal package names to a public registry.
	// --offline forces it off.
	ExternalLookups bool                 `yaml:"external_lookups"`
	EnabledModules  EnabledModulesConfig `yaml:"enabled_modules"`
	Extensions      ExtensionsConfig     `yaml:"extensions"`

	// MaxParamShapeSamples caps how many value-distinct samples of the same
	// param shape (host + path shape + method + query/form/JSON param-name-set,
	// where the path shape normalizes id-like segments: /users/1 and /users/2
	// share /users/{int}) are scanned in the dynamic-assessment phase. It
	// collapses redundant fan-out over requests that differ only in param or
	// path-id values (e.g. /search?q=1..N, /users/1..N, or repeated same-shape
	// form/JSON POSTs) without touching stored records; a request whose
	// body shape can't be seen (unseen or multipart body) is never coalesced.
	// Following the MaxFeedbackRounds convention, 0 (or unset, including
	// when a scanning profile overlays this section) means "use the built-in
	// default" (database.DefaultMaxParamShapeSamples); a negative value disables
	// coalescing entirely.
	MaxParamShapeSamples int `yaml:"max_param_shape_samples"`

	// HygieneModules overrides whether the hardening-advisory module family runs
	// (the modules tagged "hygiene": missing security headers, weak TLS
	// protocol/cipher policy, cookie attributes, CSP/HSTS/SRI/permissions-policy
	// audits). They report a missing best-practice control rather than an
	// exploitable condition and fire on nearly every response, so they are gated
	// off below --intensity deep.
	//
	//	nil (unset) - follow the intensity: off at quick/balanced, on at deep
	//	true        - always run them, at every intensity
	//	false       - never run them as part of a broad sweep, not even at deep
	//
	// This sets the default for a broad ("all") selection only. Naming them
	// explicitly (--module-tag hygiene, --module-id <id>) always wins, the same
	// way an explicit selection already bypasses the intensity tier ceiling.
	HygieneModules *bool `yaml:"hygiene_modules,omitempty"`

	// AllowRiskyPayloads unlocks risk:high probes below --intensity deep: the
	// OR-per-row and stacked time-blind SQLi payloads (which can multiply the
	// delay per row or append a statement to an UPDATE/DELETE) and whole modules
	// tagged risk:high. Deep scans always allow them. The --allow-risky-payloads
	// flag overrides this value in either direction.
	AllowRiskyPayloads bool `yaml:"allow_risky_payloads,omitempty"`

	// MaxModuleTier is a hard ceiling on the module tiers a scan runs (light,
	// moderate, heavy, intrusive). Unlike the intensity's tier ceiling it also
	// binds an explicit -m / --module-tag selection and a config allowlist: it
	// is a caller's limit, not a default. The --max-module-tier flag can only
	// lower it; the lower of the two applies.
	MaxModuleTier string `yaml:"max_module_tier,omitempty"`

	// ParamMining bounds the param-mining phase (hidden-parameter discovery),
	// which runs before the assessment at --intensity deep or with
	// --param-mining. See ParamMiningConfig.
	ParamMining ParamMiningConfig `yaml:"param_mining,omitempty"`

	// HeaderPoints selects how header insertion points are tested:
	//
	//	"gated" (default, also "") - noise headers (sec-fetch-*, priority, cache
	//	    validators, …) are never fuzzed; a header reaches only the vuln
	//	    classes that can sink it (User-Agent/Referer/X-Forwarded-For → SQLi,
	//	    cmdi; Accept-Language → SQLi, traversal; X-Forwarded-Host/Origin →
	//	    SSRF; custom headers → every class), and logged/negotiation/routing
	//	    headers are tested once per host instead of once per path.
	//	"all" - every header point reaches every module, per path (the old
	//	    behaviour). --header-fuzz=all overrides this per run.
	HeaderPoints string `yaml:"header_points,omitempty"`
}

// HeaderPointsAll reports whether header_points is "all".
func (c *DynamicAssessmentConfig) HeaderPointsAll() bool {
	return c != nil && strings.EqualFold(strings.TrimSpace(c.HeaderPoints), "all")
}

func DefaultDynamicAssessmentConfig() *DynamicAssessmentConfig {
	return &DynamicAssessmentConfig{
		MaxFeedbackRounds:    1,
		EnabledModules:       *DefaultEnabledModulesConfig(),
		Extensions:           *DefaultExtensionsConfig(),
		MaxParamShapeSamples: 3,
	}
}
