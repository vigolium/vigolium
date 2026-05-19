package prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "prototype-pollution"
	ModuleName  = "Prototype Pollution"
	ModuleShort = "Detects server-side prototype pollution via JSON injection"
)

var (
	ModuleDesc = `## Description
Detects server-side prototype pollution vulnerabilities by injecting __proto__ and
constructor.prototype properties in JSON parameters and analyzing response changes.

## Notes
- Tests JSON body parameters for prototype pollution vectors
- Injects __proto__, constructor.prototype, and __proto__[status] payloads
- Analyzes response status code and body changes after pollution
- Targets Node.js/Express applications

## References
- https://portswigger.net/web-security/prototype-pollution
- https://portswigger.net/research/server-side-prototype-pollution`

	ModuleConfirmation = "Confirmed when __proto__ or constructor.prototype injection causes observable changes in response status, headers, or body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "injection", "javascript", "moderate"}
)
