package yamlext

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// ParseSeverity converts a string severity to the severity type.
func ParseSeverity(s string) severity.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	case "low":
		return severity.Low
	case "suspect":
		return severity.Suspect
	case "info":
		return severity.Info
	default:
		return severity.Info
	}
}

// ParseScanScopes converts string scan types to bitmask.
func ParseScanScopes(types []string) modkit.ScanScope {
	var result modkit.ScanScope
	for _, t := range types {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "per_insertion_point":
			result |= modkit.ScanScopeInsertionPoint
		case "per_request":
			result |= modkit.ScanScopeRequest
		case "per_host":
			result |= modkit.ScanScopeHost
		}
	}
	if result == 0 {
		result = modkit.ScanScopeRequest
	}
	return result
}

// ParsePassiveScope converts a string scope to PassiveScanScope.
func ParsePassiveScope(s string) modkit.PassiveScanScope {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "request":
		return modkit.PassiveScanScopeRequest
	case "response":
		return modkit.PassiveScanScopeResponse
	default:
		return modkit.PassiveScanScopeBoth
	}
}

// BumpSeverity returns the next higher severity level.
func BumpSeverity(s severity.Severity) severity.Severity {
	switch s {
	case severity.Info:
		return severity.Low
	case severity.Suspect:
		return severity.Low
	case severity.Low:
		return severity.Medium
	case severity.Medium:
		return severity.High
	case severity.High:
		return severity.Critical
	default:
		return s
	}
}
