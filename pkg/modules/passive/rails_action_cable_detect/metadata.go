package rails_action_cable_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-rails-action-cable-detect"
	ModuleName  = "Rails Action Cable Detect"
	ModuleShort = "Passively detects Action Cable WebSocket endpoints and configuration in responses"
)

var (
	ModuleDesc = `## Description
Passively detects Rails Action Cable (WebSocket) usage by scanning response bodies for
Action Cable meta tags, JavaScript configuration, and WebSocket endpoint references.

## Notes
- Passive only: does not send any HTTP requests
- Detects action-cable-url meta tags in HTML
- Identifies Action Cable JavaScript references and channel subscriptions
- Scans for WebSocket endpoint paths (/cable, /websocket, /ws)
- Deduplicates by host

## References
- https://guides.rubyonrails.org/action_cable_overview.html`

	ModuleConfirmation = "Confirmed when Action Cable meta tags, JS references, or WebSocket endpoint patterns are found"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"rails", "ruby", "fingerprint", "light"}
)
