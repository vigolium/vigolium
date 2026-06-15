package open_redirect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "open-redirect"
	ModuleName  = "Open Redirect"
	ModuleShort = "Detects open redirect vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** A redirect parameter accepts an arbitrary, attacker-supplied destination without validating it against an allowlist. The server bounces visitors to any external site while appearing to come from the trusted domain.

**How it's exploited:** An attacker sets the redirect parameter to a domain they control, confirmed when the injected URL appears in a Location/Refresh header, meta refresh tag, or JavaScript redirect. This drives phishing lures and steals OAuth tokens on SSO return-URL sinks.

**Fix:** Validate redirect targets against a server-side allowlist of permitted destinations and reject or default any value pointing off-site.`

	ModuleConfirmation = "Confirmed when injected external URL appears in a redirect Location header or meta refresh tag"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"open-redirect", "moderate"}
)
