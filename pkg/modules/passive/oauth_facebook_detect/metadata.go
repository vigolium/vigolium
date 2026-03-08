package oauth_facebook_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-oauth-facebook-detect"
	ModuleName  = "Facebook OAuth Detect"
	ModuleShort = "Detects Facebook OAuth redirect parameters for security analysis"
)

var (
	ModuleDesc = `## Description
Passively detects Facebook OAuth redirect parameters in requests, flagging potential
OAuth misconfiguration or open redirect vectors in the authentication flow.

## Notes
- Scans URL parameters for Facebook OAuth redirect_uri and related parameters
- Helps identify OAuth flows that may be vulnerable to redirect manipulation

## References
- https://developers.facebook.com/docs/facebook-login/security/`

	ModuleConfirmation = "Confirmed when request URL contains Facebook OAuth parameters (client_id, redirect_uri) matching known OAuth flow patterns"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"authentication", "session", "light"}
)
