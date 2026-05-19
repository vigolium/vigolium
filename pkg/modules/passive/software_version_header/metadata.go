package software_version_header

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "software-version-header"
	ModuleName  = "Software Version Header"
	ModuleShort = "Detects HTTP headers that disclose specific software version strings"
)

var (
	ModuleDesc = `## Description
Passively detects HTTP response headers that reveal exact software version numbers.
Headers such as Server, X-Powered-By, X-AspNet-Version, and X-AspNetMvc-Version
frequently expose the underlying technology stack and its version, enabling attackers
to search for known CVEs targeting those specific versions.

## Notes
- Checks common version-disclosing headers against version number patterns
- Only reports when an actual version number is present (not just a product name)
- Deduplicates by host to report each server's version headers once
- Extracts the header name, product, and version for each finding

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/200.html`

	ModuleConfirmation = "Confirmed when HTTP response headers contain version-disclosing values with identifiable version numbers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"fingerprint", "info-disclosure", "light"}
)
