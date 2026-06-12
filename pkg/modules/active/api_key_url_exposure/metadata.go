package api_key_url_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-key-url-exposure"
	ModuleName  = "API Key in URL"
	ModuleShort = "Detects API keys that work when moved from headers to URL parameters"
)

var (
	ModuleDesc = `**What it means:** The server accepts an authentication credential (an API key or token from a header such as Authorization, X-API-Key, or X-Auth-Token) when it is supplied instead as a URL query parameter like ?access_token= or ?api_key=. This is a problem because credentials placed in URLs are not meant to be there: URLs are routinely recorded in places that headers are not.

**How it's exploited:** Because the request still succeeds with the key in the URL, that key gets written to server access logs, browser history, referrer headers sent to third-party sites, CDN and proxy logs, and shared or bookmarked links. Anyone who can read any of those locations recovers a working credential and can replay it to access the API as the victim, with no need to break authentication directly.

**Fix:** Accept credentials only from the Authorization header or a request body, reject or ignore keys passed as URL query parameters, and rotate any key that may already have been logged.`

	ModuleConfirmation = "Confirmed when the server returns a successful response with the API key passed as a URL query parameter instead of in the authorization header"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "api-security", "light"}
)
