package permissions_policy_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "permissions-policy-detect"
	ModuleName  = "Permissions Policy Detect"
	ModuleShort = "Detects missing or overly permissive Permissions-Policy headers"
)

var (
	ModuleDesc = `## Description
Passively detects missing or overly permissive Permissions-Policy (and legacy
Feature-Policy) headers that grant sensitive browser APIs to all origins.

## Notes
- Checks both Permissions-Policy and legacy Feature-Policy headers
- Flags overly permissive directives: camera=*, microphone=*, geolocation=*, payment=*, usb=*
- Flags missing header entirely
- Runs per-host to avoid duplicate findings

## References
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
- https://www.w3.org/TR/permissions-policy/`

	ModuleConfirmation = "Confirmed when Permissions-Policy header is missing or contains overly permissive directives"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
