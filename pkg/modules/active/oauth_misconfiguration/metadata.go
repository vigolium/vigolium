package oauth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oauth-misconfiguration"
	ModuleName  = "OAuth/OIDC Misconfiguration"
	ModuleShort = "Detects common OAuth/OIDC misconfigurations including open redirect and missing state"
)

var (
	ModuleDesc = `**What it means:** An OAuth/OpenID Connect authorization endpoint accepts requests it should reject. The check probes three weaknesses: a redirect_uri pointable at an attacker host, a request missing the CSRF state parameter, and a response_type downgrade to the implicit (token) flow.

**How it's exploited:** An attacker abuses an accepted redirect_uri to deliver the victim's code or token to a server they control, enabling account takeover. Missing state allows a CSRF login-binding attack, and a token downgrade exposes tokens in the URL fragment.

**Fix:** Exact-match allowlist redirect_uri, require an unguessable state value, and reject any unregistered response_type.`

	ModuleConfirmation = "Confirmed when an OAuth endpoint accepts a manipulated redirect_uri, is missing CSRF state protection, or accepts implicit flow downgrade"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "moderate"}
)
