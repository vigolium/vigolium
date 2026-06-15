package insecure_token_storage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "insecure-token-storage"
	ModuleName  = "Insecure Token Storage"
	ModuleShort = "Detects auth tokens stored in localStorage/sessionStorage"
)

var (
	ModuleDesc = `**What it means:** This flags JavaScript that stores auth tokens, API keys, or session IDs in localStorage or sessionStorage (a setItem call using a key like token, jwt, or access_token). Unlike an HttpOnly cookie, Web Storage is readable by any same-origin JavaScript, so the token has no protection from client-side script.

**How it's exploited:** Any cross-site scripting (XSS) flaw lets an injected script read and exfiltrate the token, hijacking the session. A token read into an Authorization/Bearer header confirms a live credential, raising impact to takeover.

**Fix:** Keep session and access tokens in HttpOnly, Secure, SameSite cookies, not Web Storage.`

	ModuleConfirmation = "Confirmed when JavaScript code stores auth tokens or secrets in localStorage or sessionStorage"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "javascript", "light"}
)
