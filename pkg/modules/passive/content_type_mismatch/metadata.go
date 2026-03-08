package content_type_mismatch

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-content-type-mismatch"
	ModuleName  = "Content Type Mismatch"
	ModuleShort = "Detects mismatches between Content-Type header and response body"
)

var (
	ModuleDesc = `## Description
Passively detects mismatches between the Content-Type header and actual response body
content, which can lead to MIME confusion attacks and XSS.

## Notes
- Compares declared Content-Type with detected body content signatures
- Flags JSON/XML/HTML content served with incorrect Content-Type
- Missing X-Content-Type-Options makes MIME sniffing exploitable

## References
- https://owasp.org/www-project-secure-headers/#x-content-type-options
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options`

	ModuleConfirmation = "Confirmed when the Content-Type header does not match the actual content of the response body"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"misconfiguration", "header-security", "light"}
)
