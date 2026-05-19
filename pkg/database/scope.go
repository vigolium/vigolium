package database

import (
	"path/filepath"
	"strings"
)

// ScopeEvaluator evaluates URLs against scope rules (firewall-style: first match wins, default=exclude)
type ScopeEvaluator struct {
	rules []*Scope // sorted by priority ascending (lower = higher priority)
}

// NewScopeEvaluator creates a new evaluator from pre-loaded scope rules
func NewScopeEvaluator(rules []*Scope) *ScopeEvaluator {
	return &ScopeEvaluator{rules: rules}
}

// IsInScope checks if a URL matches the scope rules.
// Iterates rules by priority. First matching rule wins.
// If no rule matches, returns false (default=exclude).
func (e *ScopeEvaluator) IsInScope(scheme, hostname string, port int, method, path string) bool {
	if len(e.rules) == 0 {
		return true // No rules defined = everything in scope
	}

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if e.ruleMatches(rule, scheme, hostname, port, method, path) {
			return rule.RuleType == "include"
		}
	}

	return false // Default: exclude
}

// ruleMatches checks if all non-empty conditions match (AND logic; empty = wildcard)
func (e *ScopeEvaluator) ruleMatches(rule *Scope, scheme, hostname string, port int, method, path string) bool {
	// Host pattern check
	if rule.HostPattern != "" {
		matched, err := filepath.Match(rule.HostPattern, hostname)
		if err != nil || !matched {
			return false
		}
	}

	// Path pattern check
	if rule.PathPattern != "" {
		matched, err := filepath.Match(rule.PathPattern, path)
		if err != nil || !matched {
			return false
		}
	}

	// Methods check
	if len(rule.Methods) > 0 {
		found := false
		for _, m := range rule.Methods {
			if strings.EqualFold(m, method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Ports check
	if len(rule.Ports) > 0 {
		found := false
		for _, p := range rule.Ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Schemes check
	if len(rule.Schemes) > 0 {
		found := false
		for _, s := range rule.Schemes {
			if strings.EqualFold(s, scheme) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
