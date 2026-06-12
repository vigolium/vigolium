package oauth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oauth-misconfiguration"
	ModuleName  = "OAuth/OIDC Misconfiguration"
	ModuleShort = "Detects common OAuth/OIDC misconfigurations including open redirect and missing state"
)

var (
	ModuleDesc = `**What it means:** An OAuth/OpenID Connect authorization endpoint accepts requests it should reject. This module probes detected OAuth endpoints for three weaknesses: a redirect_uri that can be pointed at an attacker host, an authorization request missing the CSRF state parameter, and a response_type that downgrades from code to the less safe implicit (token) flow. Each weakens the protections stopping one user's login from being hijacked.

**How it's exploited:** If redirect_uri manipulation is accepted (confirmed by re-sending a fresh attacker domain and seeing it echoed in the Location header), an attacker crafts a login link that delivers the victim's authorization code or access token to a server they control, enabling account takeover. A missing state parameter lets an attacker CSRF the flow to bind their own account to the victim's session. An accepted token downgrade (confirmed when a junk response_type is still rejected) exposes access tokens in the URL fragment, where they leak via history and referrers.

**Fix:** Exact-match allowlist redirect_uri, require an unguessable state value, and reject any unregistered response_type.`

	ModuleConfirmation = "Confirmed when an OAuth endpoint accepts a manipulated redirect_uri, is missing CSRF state protection, or accepts implicit flow downgrade"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "moderate"}
)
