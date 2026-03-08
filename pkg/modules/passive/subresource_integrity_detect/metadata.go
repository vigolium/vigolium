package subresource_integrity_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-subresource-integrity-detect"
	ModuleName  = "Subresource Integrity Detect"
	ModuleShort = "Detects external resources loaded without subresource integrity"
)

var (
	ModuleDesc = `## Description
Passively detects external scripts and stylesheets loaded without Subresource
Integrity (SRI) attributes. Missing SRI allows compromised CDNs or third-party
hosts to inject malicious code.

## Notes
- Scans HTML response bodies for script and link tags referencing external origins
- Flags external resources (http://, https://, //) that lack an integrity attribute
- Skips inline scripts, same-origin resources, and data: URIs
- Deduplicates by host+path

## References
- https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
- https://www.w3.org/TR/SRI/`

	ModuleConfirmation = "Confirmed when external script or stylesheet is loaded without an integrity attribute"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"header-security", "javascript", "light"}
)
