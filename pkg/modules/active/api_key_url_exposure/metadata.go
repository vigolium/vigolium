package api_key_url_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "api-key-url-exposure"
	ModuleName  = "API Key in URL"
	ModuleShort = "Detects API keys that work when moved from headers to URL parameters"
)

var (
	ModuleDesc = `**What it means:** A valid header credential still worked when moved into a URL parameter, while credential-free and bit-flipped controls failed. This is a transport candidate, not proof the key was logged or disclosed.

**How it's exploited:** URLs can leak credentials through access logs, browser history, referrers, proxies, and shared links.

**Fix:** Accept credentials only in headers or bodies, reject query-string keys, and rotate keys that may have been logged.`

	ModuleConfirmation = "Candidate after isolated no-credential and bit-flipped controls plus two stable valid URL replays matching the authenticated baseline"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "api-security", "light"}
)
