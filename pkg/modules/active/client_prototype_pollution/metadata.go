package client_prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-client-prototype-pollution"
	ModuleName  = "Client-Side Prototype Pollution"
	ModuleShort = "Detects client-side prototype pollution via JavaScript static analysis"
)

var (
	ModuleDesc = `## Description
Detects client-side prototype pollution vulnerabilities by analyzing JavaScript code
on the page for known vulnerable URL parameter parsing patterns (sources) and
exploitable property access patterns (gadgets).

## Notes
- Different from server-side prototype pollution: targets browser-side JavaScript, not JSON bodies
- Analyzes inline scripts and fetches external JS files (skipping CDN libraries)
- Detects source patterns (jQuery.extend, lodash.merge, custom parsers)
- Detects gadget patterns (innerHTML, eval, script.src assignments)
- Sends probe requests to verify URL parameter acceptance
- Host-level deduplication (scans once per host)

## References
- https://portswigger.net/web-security/prototype-pollution
- https://portswigger.net/web-security/prototype-pollution/client-side
- https://portswigger.net/research/widespread-prototype-pollution-gadgets`

	ModuleConfirmation = "Confirmed when JavaScript static analysis identifies known prototype pollution source patterns in the page's scripts"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "xss", "light"}
)
