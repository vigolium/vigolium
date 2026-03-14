package yamlext

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLLintIssue represents a single lint finding for a YAML extension.
type YAMLLintIssue struct {
	Severity string // "error" or "warning"
	Line     int    // 1-based, 0 if unknown
	Message  string
}

// YAMLLintResult holds the outcome of linting a single YAML extension file.
type YAMLLintResult struct {
	Path   string
	Issues []YAMLLintIssue
}

// HasErrors returns true if any issue is an error.
func (r *YAMLLintResult) HasErrors() bool {
	for _, i := range r.Issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

// LintYAML validates a YAML extension source string and returns any issues found.
func LintYAML(source, filename string) *YAMLLintResult {
	result := &YAMLLintResult{Path: filename}

	// Phase 1: YAML parse check
	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(source), &raw); err != nil {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error",
			Message:  fmt.Sprintf("YAML parse error: %v", err),
		})
		return result
	}

	// Phase 2: Unmarshal into schema
	var def ExtensionDef
	if err := yaml.Unmarshal([]byte(source), &def); err != nil {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error",
			Message:  fmt.Sprintf("schema error: %v", err),
		})
		return result
	}

	// Phase 3: Required field validation
	if def.Type == "" {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error",
			Message:  "missing required field 'type'",
		})
		return result // can't validate further without type
	}

	validTypes := map[string]bool{"active": true, "passive": true, "pre_hook": true, "post_hook": true}
	if !validTypes[def.Type] {
		result.Issues = append(result.Issues, YAMLLintIssue{
			Severity: "error",
			Message:  fmt.Sprintf("invalid type %q; must be one of: active, passive, pre_hook, post_hook", def.Type),
		})
		return result
	}

	// Phase 4: Type-specific validation
	switch def.Type {
	case "active":
		result.Issues = append(result.Issues, lintActiveYAML(&def)...)
	case "passive":
		result.Issues = append(result.Issues, lintPassiveYAML(&def)...)
	case "pre_hook":
		result.Issues = append(result.Issues, lintPreHookYAML(&def)...)
	case "post_hook":
		result.Issues = append(result.Issues, lintPostHookYAML(&def)...)
	}

	// Phase 5: Common validation
	result.Issues = append(result.Issues, lintCommonYAML(&def)...)

	return result
}

// lintCommonYAML validates fields common to all YAML extension types.
func lintCommonYAML(def *ExtensionDef) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.ID == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "missing 'id' field (will be auto-generated from filename)",
		})
	}

	// Validate severity
	if def.Severity != "" && !isValidYAMLSeverity(def.Severity) {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("unknown severity %q; expected one of: critical, high, medium, low, info, suspect", def.Severity),
		})
	}

	// Validate confidence
	if def.Confidence != "" {
		validConfidences := map[string]bool{"tentative": true, "firm": true, "certain": true}
		if !validConfidences[strings.ToLower(def.Confidence)] {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Message:  fmt.Sprintf("unknown confidence %q; expected one of: tentative, firm, certain", def.Confidence),
			})
		}
	}

	// Validate scan_types
	for _, st := range def.ScanTypes {
		if !isValidYAMLScanType(st) {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Message:  fmt.Sprintf("unknown scan type %q; expected: per_insertion_point, per_request, per_host", st),
			})
		}
	}

	// Validate matchers_condition
	if def.MatchersCondition != "" && def.MatchersCondition != "or" && def.MatchersCondition != "and" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  fmt.Sprintf("unknown matchers_condition %q; expected: or, and", def.MatchersCondition),
		})
	}

	// Validate regex patterns in matchers
	for i, m := range def.Matchers {
		if m.Regex != "" {
			if _, err := regexp.Compile(m.Regex); err != nil {
				issues = append(issues, YAMLLintIssue{
					Severity: "error",
					Message:  fmt.Sprintf("matchers[%d]: invalid regex %q: %v", i, m.Regex, err),
				})
			}
		}
		if m.Type != "" {
			validMatcherTypes := map[string]bool{"body": true, "header": true, "status": true, "js": true}
			if !validMatcherTypes[m.Type] {
				issues = append(issues, YAMLLintIssue{
					Severity: "warning",
					Message:  fmt.Sprintf("matchers[%d]: unknown type %q; expected: body, header, status, js", i, m.Type),
				})
			}
		}
		if m.Type == "header" && m.Name == "" {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Message:  fmt.Sprintf("matchers[%d]: header matcher missing 'name' field", i),
			})
		}
		if m.Type == "status" && len(m.Codes) == 0 {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Message:  fmt.Sprintf("matchers[%d]: status matcher missing 'codes' field", i),
			})
		}
	}

	// Validate regex patterns in rules
	for i, rule := range def.Rules {
		if rule.Match.Regex != "" {
			if _, err := regexp.Compile(rule.Match.Regex); err != nil {
				issues = append(issues, YAMLLintIssue{
					Severity: "error",
					Message:  fmt.Sprintf("rules[%d].match.regex: invalid regex %q: %v", i, rule.Match.Regex, err),
				})
			}
		}
		if rule.Match.BodyRegex != "" {
			if _, err := regexp.Compile(rule.Match.BodyRegex); err != nil {
				issues = append(issues, YAMLLintIssue{
					Severity: "error",
					Message:  fmt.Sprintf("rules[%d].match.body_regex: invalid regex %q: %v", i, rule.Match.BodyRegex, err),
				})
			}
		}
	}

	return issues
}

// lintActiveYAML validates an active YAML extension.
func lintActiveYAML(def *ExtensionDef) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.Severity == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "active extension should declare a severity",
		})
	}

	// Active module needs payloads+matchers, or rules, or a script
	hasPayloads := len(def.Payloads) > 0
	hasMatchers := len(def.Matchers) > 0
	hasRules := len(def.Rules) > 0
	hasScript := def.Script != ""

	if !hasPayloads && !hasRules && !hasScript {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "active extension has no payloads, rules, or script — it won't generate any findings",
		})
	}

	if hasPayloads && !hasMatchers && !hasRules {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "active extension has payloads but no matchers or rules to check responses",
		})
	}

	return issues
}

// lintPassiveYAML validates a passive YAML extension.
func lintPassiveYAML(def *ExtensionDef) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.Scope != "" {
		validScopes := map[string]bool{"request": true, "response": true, "both": true}
		if !validScopes[def.Scope] {
			issues = append(issues, YAMLLintIssue{
				Severity: "warning",
				Message:  fmt.Sprintf("unknown scope %q; expected: request, response, both", def.Scope),
			})
		}
	}

	// Passive needs matchers or rules or a script
	if len(def.Matchers) == 0 && len(def.Rules) == 0 && def.Script == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "passive extension has no matchers, rules, or script — it won't generate any findings",
		})
	}

	return issues
}

// lintPreHookYAML validates a pre_hook YAML extension.
func lintPreHookYAML(def *ExtensionDef) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if len(def.AddHeaders) == 0 && len(def.SkipExtensions) == 0 && def.Script == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "pre_hook has no add_headers, skip_extensions, or script — it won't do anything",
		})
	}

	return issues
}

// lintPostHookYAML validates a post_hook YAML extension.
func lintPostHookYAML(def *ExtensionDef) []YAMLLintIssue {
	var issues []YAMLLintIssue

	if def.Escalate == nil && def.DropWhen == nil && def.Script == "" {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "post_hook has no escalate, drop_when, or script — it won't do anything",
		})
	}

	if def.Escalate != nil && len(def.Escalate.WhenURLContains) == 0 {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "escalate has no when_url_contains patterns — it will never trigger",
		})
	}

	if def.DropWhen != nil && len(def.DropWhen.Severity) == 0 && len(def.DropWhen.URLContains) == 0 {
		issues = append(issues, YAMLLintIssue{
			Severity: "warning",
			Message:  "drop_when has no severity or url_contains conditions — it will never trigger",
		})
	}

	return issues
}

func isValidYAMLSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info", "suspect":
		return true
	}
	return false
}

func isValidYAMLScanType(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "per_insertion_point", "per_request", "per_host":
		return true
	}
	return false
}
