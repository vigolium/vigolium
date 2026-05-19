package discovery

import (
	"regexp"
	"strings"
)

// templateVarRegex matches template variable patterns:
// - ${...} or ${... (dollar-brace, complete or incomplete)
// - {word} or {word (curly brace starting with letter, complete or incomplete)
var templateVarRegex = regexp.MustCompile(`\$\{[^}]*\}?|\{[a-zA-Z][a-zA-Z0-9_]*\}?`)

// defaultTemplateValue is the replacement value for template variables.
const defaultTemplateValue = "1"

// ContainsTemplateVar checks if string contains any template variable syntax.
// Matches: ${...}, ${incomplete, {word}, {incomplete
func ContainsTemplateVar(s string) bool {
	// Fast check for ${
	if strings.Contains(s, "${") {
		return true
	}
	// Check for {letter pattern (template, not JSON)
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '{' {
			c := s[i+1]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				return true
			}
		}
	}
	return false
}

// ReplaceTemplateVars replaces all template patterns with a fixed value.
// Patterns: ${...}, ${incomplete, {word}, {incomplete
// Example: "user_id=${userId}&name=test" → "user_id=1&name=test"
// Example: "/api/{id}/profile" → "/api/1/profile"
func ReplaceTemplateVars(s string) string {
	if !ContainsTemplateVar(s) {
		return s
	}
	return templateVarRegex.ReplaceAllString(s, defaultTemplateValue)
}
