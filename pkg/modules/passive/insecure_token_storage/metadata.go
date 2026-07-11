package insecure_token_storage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "insecure-token-storage"
	ModuleName  = "Insecure Token Storage"
	ModuleShort = "Detects auth tokens stored in localStorage/sessionStorage"
)

var (
	ModuleDesc = `**What it means:** JavaScript writes an authentication token, API key, or session identifier to localStorage or sessionStorage. Strong token keys are candidates; ambiguous keys are observations. Web Storage is readable by same-origin scripts.

**How it's exploited:** A separate XSS flaw can read and exfiltrate the stored token. Authorization-header use strengthens the storage link but does not prove token validity or takeover.

**Fix:** Keep session and access tokens in HttpOnly, Secure, SameSite cookies instead of Web Storage.`

	ModuleConfirmation = "Candidate for connected strong-token storage/use patterns; ambiguous keys remain observations, and confirmation requires a valid token plus an exploit path such as XSS"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "javascript", "light"}
)
