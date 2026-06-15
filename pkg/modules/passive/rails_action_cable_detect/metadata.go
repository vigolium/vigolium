package rails_action_cable_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "rails-action-cable-detect"
	ModuleName  = "Rails Action Cable Detect"
	ModuleShort = "Passively detects Action Cable WebSocket endpoints and configuration in responses"
)

var (
	ModuleDesc = `**What it means:** The application exposes Rails Action Cable, its WebSocket layer for real-time messaging, identified passively via Action Cable meta tags, JS references, channel subscriptions, or endpoint paths such as /cable. An informational fingerprint that reveals a WebSocket attack surface worth reviewing.

**How it's exploited:** If origin checks (allowed_request_origins) or per-channel authorization are weak, an attacker connects cross-origin (Cross-Site WebSocket Hijacking) using a victim's session cookies to subscribe to channels or push unauthorized messages.

**Fix:** Restrict Action Cable to trusted origins via allowed_request_origins and enforce authentication and authorization in connection and channel subscribe logic.`

	ModuleConfirmation = "Confirmed when Action Cable meta tags, JS references, or WebSocket endpoint patterns are found"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"rails", "ruby", "fingerprint", "light"}
)
