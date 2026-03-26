package xss_scanner

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-scanner"
	ModuleName  = "XSS Scanner"
	ModuleShort = "Detects reflected XSS vulnerabilities"
)

var (
	ModuleDesc = `## Description
Full reflected XSS scanner using context-aware payload generation. Analyzes reflection
context (HTML body, attributes, JavaScript, URL) and generates targeted payloads.

## Notes
- Context-aware: adapts payloads based on where the reflection occurs
- Uses strategy-based payload selection with atomic, composite, and contextual strategies
- Includes SSTI scanning as a secondary check

## References
- https://owasp.org/www-community/attacks/xss/`

	ModuleConfirmation = "Confirmed when a crafted XSS payload executes or is reflected in an exploitable context without encoding"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"injection", "xss", "moderate"}
)
