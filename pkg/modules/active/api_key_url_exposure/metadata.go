package api_key_url_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-key-url-exposure"
	ModuleName  = "API Key in URL"
	ModuleShort = "Detects API keys that work when moved from headers to URL parameters"
)

var (
	ModuleDesc = `**What it means:** The server accepts an authentication credential (normally an Authorization, X-API-Key, or X-Auth-Token header) when supplied instead as a URL query parameter like ?access_token= or ?api_key=. URLs get recorded where headers never are.

**How it's exploited:** Since the request still succeeds, the key lands in access logs, browser history, referrer headers, proxy logs, and shared links. Anyone reading those recovers a working credential and replays it as the victim.

**Fix:** Accept credentials only from the Authorization header or request body, reject keys passed as query parameters, and rotate any key that may have been logged.`

	ModuleConfirmation = "Confirmed when the server returns a successful response with the API key passed as a URL query parameter instead of in the authorization header"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "api-security", "light"}
)
