package dom_xss_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-xss-detect"
	ModuleName  = "DOM XSS Detect"
	ModuleShort = "Detects potential DOM-based XSS patterns in responses"
)

var (
	ModuleDesc = `## Description
Passively detects potential DOM-based XSS patterns by analyzing JavaScript code in
responses for dangerous source-to-sink data flows.

## Notes
- Scans response bodies for known DOM XSS source patterns (location.hash, document.referrer, etc.)
- Identifies dangerous sink patterns (innerHTML, eval, document.write, etc.)
- Pattern-based detection; manual verification recommended

## References
- https://owasp.org/www-community/attacks/DOM_Based_XSS`

	ModuleConfirmation = "Indicated when response JavaScript contains known source-to-sink patterns that could enable DOM-based XSS"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "javascript", "light"}
)
