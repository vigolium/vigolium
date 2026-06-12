package insecure_token_storage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "insecure-token-storage"
	ModuleName  = "Insecure Token Storage"
	ModuleShort = "Detects auth tokens stored in localStorage/sessionStorage"
)

var (
	ModuleDesc = `**What it means:** This passively flags JavaScript that stores authentication tokens, API keys, or session identifiers in the browser's localStorage or sessionStorage (for example a setItem call or bracket assignment using a key like token, jwt, auth, access_token, or api_key). Unlike an HttpOnly cookie, anything in Web Storage is fully readable by any JavaScript running in the same origin, so a token kept there has no protection against client-side script access.
**How it's exploited:** If the application has any cross-site scripting (XSS) flaw, an injected script can read the stored token straight out of Web Storage and exfiltrate it, letting the attacker impersonate the victim and hijack their session or call authenticated APIs. The high-severity variant (a token read from localStorage into an Authorization or Bearer header) confirms the stored value is a live credential, raising the impact of any XSS to full account takeover.
**Fix:** Keep session and access tokens in HttpOnly, Secure, SameSite cookies instead of localStorage or sessionStorage, and avoid persisting long-lived credentials in browser-accessible storage.`

	ModuleConfirmation = "Confirmed when JavaScript code stores auth tokens or secrets in localStorage or sessionStorage"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"authentication", "session", "javascript", "light"}
)
