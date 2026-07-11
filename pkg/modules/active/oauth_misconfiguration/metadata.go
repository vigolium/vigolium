package oauth_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oauth-misconfiguration"
	ModuleName  = "OAuth/OIDC Misconfiguration"
	ModuleShort = "Detects common OAuth/OIDC misconfigurations including open redirect and missing state"
)

var (
	ModuleDesc = `**What it means:** The scanner tests an OAuth/OIDC authorization surface for attacker-controlled redirect_uri handling, a missing state parameter, and acceptance of response_type=token.

**How it's exploited:** An attacker-host redirect can support phishing or credential delivery. Missing state is only a flow observation until login CSRF is reproduced. Implicit-flow acceptance is a candidate until the server actually issues an access token; invalid response types must be rejected in repeated controls.

**Fix:** Exact-match allowlist redirect_uri, require an unguessable state value, and reject any unregistered response_type.`

	ModuleConfirmation = "Fresh attacker-authority reflection confirms open redirect; state absence is observational; response-type acceptance requires two token/invalid differentials and becomes a finding only when a token is issued"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "moderate"}
)
