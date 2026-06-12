package openredirect_params

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "openredirect-params"
	ModuleName  = "Open Redirect Params"
	ModuleShort = "Detects URL parameters commonly used for open redirects"
)

var (
	ModuleDesc = `**What it means:** This is an informational triage signal, not a confirmed vulnerability. The request URL carries a query parameter whose name (matching redirect, callback, cb, url, uri, link, or location) is commonly used to control where a server or page sends the user next. Such parameters are a frequent source of open redirect flaws if the destination is not validated.

**How it's exploited:** If the application redirects to this parameter's value without an allowlist, an attacker crafts a link to the trusted site with the parameter set to an attacker-controlled URL, so victims who click are forwarded to a phishing or malware page while believing they stayed on the trusted domain. This module only flags the parameter name by pattern; it does not send any request to confirm a redirect actually occurs, so the parameter must be verified with the active open redirect module before treating it as exploitable.

**Fix:** Validate any redirect target against a server-side allowlist of permitted destinations and reject or rewrite absolute or off-domain URLs.`

	ModuleConfirmation = "Indicated when URL contains parameters with redirect-associated names (redirect, url, next, return, goto)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"open-redirect", "light"}
)
