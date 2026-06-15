package websocket_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "websocket-security"
	ModuleName  = "WebSocket Security"
	ModuleShort = "Detects insecure WebSocket upgrade policies and missing origin validation"
)

var (
	ModuleDesc = `**What it means:** A WebSocket endpoint completed a full upgrade handshake (101 Switching Protocols, valid Sec-WebSocket-Accept) even with an attacker-controlled or missing Origin. The server does not validate connection origin, so any website can open an authenticated WebSocket on a victim's behalf.

**How it's exploited:** A malicious page scripts a connection; the browser attaches the victim's cookies and the server skips origin checks, so the attacker rides the session (Cross-Site WebSocket Hijacking) to act as the victim.

**Fix:** Validate the Origin header on the upgrade, reject unexpected or missing origins, and bind the connection to a per-session CSRF-style token.`

	ModuleConfirmation = "Confirmed when the server accepts a WebSocket upgrade request from an unauthorized or missing origin, indicating missing origin validation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "session", "light"}
)
