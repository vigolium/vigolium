package permissions_policy_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "permissions-policy-detect"
	ModuleName  = "Permissions Policy Detect"
	ModuleShort = "Detects missing or overly permissive Permissions-Policy headers"
)

var (
	ModuleDesc = `**What it means:** This HTML response either omits the Permissions-Policy header entirely or sets sensitive browser features (camera, microphone, geolocation, payment, usb) to a wildcard that grants them to all origins. The header controls which browser capabilities the page and any embedded third-party frames are allowed to use, so a missing or wildcard policy removes a defense-in-depth control over powerful device APIs. This is an informational hardening gap, not a directly exploitable flaw.

**How it's exploited:** If the site is also vulnerable to cross-site scripting or embeds untrusted iframes/third-party content, the absent or permissive policy lets that injected or embedded code reach privileged APIs (such as accessing the camera, microphone, or geolocation, or invoking the Payment Request API) that a restrictive policy would otherwise block. The legacy Feature-Policy header is also flagged because it is superseded and may indicate outdated configuration.

**Fix:** Send a Permissions-Policy header that explicitly disables or tightly scopes sensitive features (for example camera=(), microphone=(), geolocation=(self)) and replace any legacy Feature-Policy header.`

	ModuleConfirmation = "Confirmed when Permissions-Policy header is missing or contains overly permissive directives"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "misconfiguration", "light"}
)
