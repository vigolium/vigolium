package mixed_content_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-mixed-content-detect"
	ModuleName  = "Mixed Content Detect"
	ModuleShort = "Detects mixed HTTP/HTTPS content in responses"
)

var (
	ModuleDesc = `## Description
Passively detects mixed content issues where HTTPS pages load resources over
insecure HTTP connections, potentially exposing data to interception.

## Notes
- Scans HTML response bodies for HTTP URLs in src, href, and action attributes
- Only checks responses from HTTPS origins
- Flags both active (scripts, iframes) and passive (images, stylesheets) mixed content

## References
- https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content
- https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning`

	ModuleConfirmation = "Confirmed when HTTPS page contains references to resources loaded over insecure HTTP"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags = []string{"misconfiguration", "cryptography", "light"}
)
