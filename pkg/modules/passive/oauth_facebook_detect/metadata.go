package oauth_facebook_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oauth-facebook-detect"
	ModuleName  = "Facebook OAuth Detect"
	ModuleShort = "Detects Facebook OAuth redirect parameters for security analysis"
)

var (
	ModuleDesc = `**What it means:** A request to www.facebook.com carries a redirect-control parameter (redirect_uri or next) as part of a Facebook OAuth login flow. This marks where the application hands control back to a return URL after authentication, which is the exact spot that must be tightly validated to avoid open-redirect and OAuth token-theft issues.

**How it's exploited:** The detection itself is informational and does not prove a flaw. It pinpoints the OAuth return-URL parameter so a reviewer can test whether an attacker-supplied value is accepted; if the redirect target is not strictly whitelisted, an attacker can craft a login link that sends the victim or their authorization code or access token to an attacker-controlled site after login.

**Fix:** Strictly validate the OAuth redirect_uri against an exact allowlist of registered callback URLs (full path, no wildcard host matching) on both the application and the Facebook app configuration.`

	ModuleConfirmation = "Confirmed when request URL contains Facebook OAuth parameters (client_id, redirect_uri) matching known OAuth flow patterns"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "light"}
)
