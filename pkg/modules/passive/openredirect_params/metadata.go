package openredirect_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "openredirect-params"
	ModuleName  = "Open Redirect Params"
	ModuleShort = "Detects URL parameters commonly used for open redirects"
)

var (
	ModuleDesc = `**What it means:** An informational triage signal, not a confirmed flaw. The request URL carries a query parameter whose name (redirect, callback, cb, url, uri, link, location) commonly controls where the app sends the user next, a frequent source of open redirect if unvalidated.

**How it's exploited:** If the app redirects to this value without an allowlist, a crafted link sets it to an attacker URL, forwarding victims to phishing while they believe they stayed on the trusted domain. Verify with the active open redirect module.

**Fix:** Validate redirect targets against a server-side allowlist and reject or rewrite off-domain URLs.`

	ModuleConfirmation = "Indicated when URL contains parameters with redirect-associated names (redirect, url, next, return, goto)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"open-redirect", "light"}
)
