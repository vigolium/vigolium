package oauth_facebook_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "oauth-facebook-detect"
	ModuleName  = "Facebook OAuth Detect"
	ModuleShort = "Detects Facebook OAuth redirect parameters for security analysis"
)

var (
	ModuleDesc = `**What it means:** A request to www.facebook.com carries a redirect-control parameter (redirect_uri or next) in a Facebook OAuth login flow, marking the return URL trusted after authentication. Informational recon, not a confirmed flaw.

**How it's exploited:** The detection pinpoints the OAuth return-URL parameter so a reviewer can test whether an attacker value is accepted. If it is not strictly allowlisted, a crafted login link can send the victim or their authorization code to an attacker site.

**Fix:** Strictly validate redirect_uri against an exact allowlist of registered callback URLs (full path, no wildcard host).`

	ModuleConfirmation = "Confirmed when request URL contains Facebook OAuth parameters (client_id, redirect_uri) matching known OAuth flow patterns"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "light"}
)
