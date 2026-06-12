package sensitive_url_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-url-params"
	ModuleName  = "Sensitive URL Params"
	ModuleShort = "Detects sensitive data in URL query parameters"
)

var (
	ModuleDesc = `**What it means:** The application passes a sensitive value in a URL query parameter whose name matches a credential or secret pattern (for example password, token, api_key, secret, access_token, session_id, ssn, cvv, or pin). Values placed in URLs are not private: they are recorded in server and proxy access logs and browser history, and leaked to third-party sites via the Referer header, exposing secrets beyond the intended request. This module flags the parameter by name and masks the value; it does not verify the value is live.

**How it's exploited:** An attacker or insider with access to server, CDN, or analytics logs, or a linked third-party site that receives the Referer, can harvest the leaked password, token, or key and replay it to authenticate, hijack a session, or call the API as the victim. Shared browser history or a screenshot can also expose it.

**Fix:** Move sensitive values out of the URL into the request body or an Authorization header, and rotate any credential previously exposed in a query string.`

	ModuleConfirmation = "Indicated when URL query parameters contain names or values matching sensitive data patterns (password, token, key, secret)"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "light"}
)
