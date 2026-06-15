package permissions_policy_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "permissions-policy-detect"
	ModuleName  = "Permissions Policy Detect"
	ModuleShort = "Detects missing or overly permissive Permissions-Policy headers"
)

var (
	ModuleDesc = `**What it means:** This HTML response omits the Permissions-Policy header or grants sensitive browser features (camera, microphone, geolocation, payment) to all origins via a wildcard. An informational hardening gap, not a directly exploitable flaw.

**How it's exploited:** If the site also has cross-site scripting or embeds untrusted iframes, the missing or permissive policy lets injected code reach privileged APIs a restrictive policy would block. The legacy Feature-Policy header is also flagged as superseded.

**Fix:** Send a Permissions-Policy header that disables or scopes sensitive features (camera=(), microphone=(), geolocation=(self)) and replace any legacy Feature-Policy header.`

	ModuleConfirmation = "Confirmed when Permissions-Policy header is missing or contains overly permissive directives"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
