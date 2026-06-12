package rails_action_cable_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-action-cable-detect"
	ModuleName  = "Rails Action Cable Detect"
	ModuleShort = "Passively detects Action Cable WebSocket endpoints and configuration in responses"
)

var (
	ModuleDesc = `**What it means:** The application exposes Rails Action Cable, the WebSocket layer used for real-time messaging and channel subscriptions. This was identified passively by spotting Action Cable meta tags, JavaScript references, channel subscription calls, or WebSocket endpoint paths (such as /cable) in the HTML or JS response. It is an informational fingerprint, not a vulnerability on its own, but it reveals a real-time WebSocket attack surface that warrants review.

**How it's exploited:** Knowing Action Cable is in use lets an attacker target the WebSocket endpoint directly: if origin checks (allowed_request_origins) or per-channel authentication and authorization are weak or missing, they can connect cross-origin (Cross-Site WebSocket Hijacking) using a victim's session cookies and subscribe to channels or push messages they should not have access to. The disclosure also helps map the technology stack for further Rails-specific probing.

**Fix:** Restrict Action Cable to trusted origins via allowed_request_origins and enforce authentication and authorization in connection and channel subscribe logic.`

	ModuleConfirmation = "Confirmed when Action Cable meta tags, JS references, or WebSocket endpoint patterns are found"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "fingerprint", "light"}
)
