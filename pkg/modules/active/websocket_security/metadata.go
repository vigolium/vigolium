package websocket_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "websocket-security"
	ModuleName  = "WebSocket Security"
	ModuleShort = "Detects insecure WebSocket upgrade policies and missing origin validation"
)

var (
	ModuleDesc = `**What it means:** A WebSocket endpoint completed a full upgrade handshake (101 Switching Protocols with a valid Sec-WebSocket-Accept) even when the request carried an attacker-controlled Origin or no Origin header at all. This means the server does not validate the connection's origin, so any website can open an authenticated WebSocket to it on a victim's behalf.

**How it's exploited:** A malicious page in a victim's browser scripts a WebSocket connection to the vulnerable endpoint. Because the browser automatically attaches the victim's cookies and the server skips origin validation, the attacker's site rides the victim's authenticated session (Cross-Site WebSocket Hijacking), letting it read pushed data and send messages as the victim to steal information or perform actions.

**Fix:** Validate the Origin header on the WebSocket upgrade and reject any unexpected or missing origin, and bind the connection to a per-session CSRF-style token rather than relying on ambient cookies alone.`

	ModuleConfirmation = "Confirmed when the server accepts a WebSocket upgrade request from an unauthorized or missing origin, indicating missing origin validation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "session", "light"}
)
