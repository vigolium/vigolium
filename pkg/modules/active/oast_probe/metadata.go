package oast_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oast-probe"
	ModuleName  = "OAST Probe"
	ModuleShort = "Detects blind vulnerabilities via out-of-band callbacks (DNS/HTTP)"
)

var (
	ModuleDesc = `**What it means:** A server-side component behind the application was tricked into making an outbound network request to an attacker-chosen destination, confirmed by an out-of-band DNS or HTTP callback to a unique tracking host. This is blind server-side request forgery (SSRF): a backend, reverse proxy, or routing layer fetched or resolved a URL supplied in a request header or a URL-like parameter, with no visible response signal.

**How it's exploited:** An attacker injects an internal address (such as cloud metadata endpoints, internal admin panels, or other private hosts) into the same header or parameter to reach systems the server can access but the attacker cannot, enabling credential theft, internal reconnaissance, or pivoting deeper into the network. A confirmed HTTP callback shows the backend actually retrieves attacker-controlled URLs; a DNS-only callback proves name-resolution reach.

**Fix:** Validate and allowlist outbound destinations, block requests to internal and link-local ranges, and stop backend components from fetching or resolving attacker-controlled URLs from request headers and parameters.`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "ssrf", "rce", "heavy"}
)
