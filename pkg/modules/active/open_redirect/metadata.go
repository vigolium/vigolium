package open_redirect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "open-redirect"
	ModuleName  = "Open Redirect"
	ModuleShort = "Detects open redirect vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A request parameter that controls where the application redirects accepts an arbitrary, attacker-supplied destination without validating it against an allowlist. The server sends the browser to whatever URL the attacker puts in that parameter, so the application can be used to bounce visitors to any external site while appearing to originate from the trusted domain.

**How it's exploited:** An attacker crafts a link to the legitimate site with the redirect parameter set to a domain they control (the scanner confirmed this by injecting external and look-alike subdomain URLs and observing the response redirect there via a Location/Refresh header, a meta refresh tag, or a JavaScript location/window redirect, re-verified across multiple rounds with fresh random domains). This is used for convincing phishing and credential-harvesting lures, to bypass redirect-based allowlists, and to steal OAuth tokens or auth codes when the sink is an OAuth/SSO return-URL parameter.

**Fix:** Validate redirect targets against a server-side allowlist of permitted destinations and reject or default any value pointing off-site.`

	ModuleConfirmation = "Confirmed when injected external URL appears in a redirect Location header or meta refresh tag"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"open-redirect", "moderate"}
)
