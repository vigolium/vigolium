// Package yamlext implements the YAML extension system (.vgm.yaml) for Vigolium.
// YAML extensions provide a declarative alternative to JavaScript extensions for
// common scanning patterns: metadata + modify request + check response.
package yamlext

// ExtensionDef is the top-level schema for a .vgm.yaml extension file.
type ExtensionDef struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`        // active, passive, pre_hook, post_hook
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Scope       string `yaml:"scope"` // passive: request, response, both

	Confidence           string   `yaml:"confidence"` // tentative, firm, certain
	ScanTypes            []string `yaml:"scan_types"`
	Tags                 []string `yaml:"tags"`
	ConfirmationCriteria string   `yaml:"confirmation_criteria"`

	// Active/Passive scanning
	Payloads          []string     `yaml:"payloads"`
	Matchers          []MatcherDef `yaml:"matchers"`
	MatchersCondition string       `yaml:"matchers_condition"` // or (default), and
	Finding           *FindingDef  `yaml:"finding"`
	Rules             []RuleDef    `yaml:"rules"`

	// Pre-hook
	AddHeaders     map[string]string `yaml:"add_headers"`
	SkipExtensions []string          `yaml:"skip_extensions"`
	SkipWhen       *SkipWhenDef      `yaml:"skip_when"`

	// Post-hook
	Escalate *EscalateDef `yaml:"escalate"`
	DropWhen *DropWhenDef `yaml:"drop_when"`

	// JS escape hatch
	Script string `yaml:"script"`

	sourcePath string // set during loading, not from YAML
}

// SourcePath returns the file path the extension was loaded from.
func (d *ExtensionDef) SourcePath() string { return d.sourcePath }

// MatcherDef defines a single match condition.
type MatcherDef struct {
	Type     string `yaml:"type"`     // body (default), header, status, js
	Contains string `yaml:"contains"`
	Regex    string `yaml:"regex"`
	Name     string `yaml:"name"`  // header name (for type: header)
	Codes    []int  `yaml:"codes"` // for type: status
	Negate   bool   `yaml:"negate"`
	Code     string `yaml:"code"` // for type: js
}

// FindingDef defines the output finding template.
type FindingDef struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"` // override module severity
	Matched     string `yaml:"matched"`
}

// RuleDef is a match + finding pair used in rules-based mode.
type RuleDef struct {
	Match   RuleMatchDef `yaml:"match"`
	Finding FindingDef   `yaml:"finding"`
}

// RuleMatchDef defines match conditions for a rule.
type RuleMatchDef struct {
	ResponseHeader string `yaml:"response_header"` // header exists/value check
	BodyContains   string `yaml:"body_contains"`
	BodyRegex      string `yaml:"body_regex"`
	Regex          string `yaml:"regex"`    // value regex (for headers)
	Contains       string `yaml:"contains"` // value contains
	Status         []int  `yaml:"status"`
}

// SkipWhenDef defines conditions for skipping a pre-hook.
type SkipWhenDef struct {
	ConfigEmpty string   `yaml:"config_empty"`
	URLContains []string `yaml:"url_contains"`
}

// EscalateDef defines severity escalation for post-hooks.
type EscalateDef struct {
	WhenURLContains []string `yaml:"when_url_contains"`
	Tag             string   `yaml:"tag"`
	BumpSeverity    bool     `yaml:"bump_severity"`
}

// DropWhenDef defines conditions for dropping a result.
type DropWhenDef struct {
	Severity    []string `yaml:"severity"`
	URLContains []string `yaml:"url_contains"`
}
