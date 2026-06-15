package oast_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oast-probe"
	ModuleName  = "OAST Probe"
	ModuleShort = "Detects blind vulnerabilities via out-of-band callbacks (DNS/HTTP)"
)

var (
	ModuleDesc = `**What it means:** A backend, reverse proxy, or routing layer was tricked into an outbound request to an attacker-chosen destination, confirmed by an out-of-band DNS or HTTP callback. This is blind server-side request forgery (SSRF) from a URL in a request header or parameter.

**How it's exploited:** An attacker injects an internal address (cloud metadata, admin panels, private hosts) into the same field to reach systems only the server can access, enabling credential theft, reconnaissance, or pivoting deeper.

**Fix:** Validate and allowlist outbound destinations, block internal and link-local ranges, and stop backends from fetching attacker-controlled URLs.`

	ModuleConfirmation = "Confirmed when target server makes outbound DNS or HTTP request to OAST callback URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "ssrf", "rce", "heavy"}
)
