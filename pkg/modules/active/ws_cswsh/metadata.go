package ws_cswsh

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-cswsh"
	ModuleName  = "WebSocket CSWSH"
	ModuleShort = "Tests for Cross-Site WebSocket Hijacking via insufficient origin validation"
)

var (
	ModuleDesc = `**What it means:** A WebSocket endpoint completed a genuine upgrade handshake (101 Switching Protocols, Sec-WebSocket-Accept) with an attacker-controlled, null, or missing Origin. The server does not validate connection origin, exposing it to Cross-Site WebSocket Hijacking (CSWSH) - effectively CSRF for the WebSocket channel.

**How it's exploited:** A malicious page, visited by a logged-in victim, silently opens a WebSocket to the endpoint. The browser attaches the victim's cookies, so the connection is authenticated as the victim and the script acts as them.

**Fix:** Validate the Origin header against an allowlist, reject mismatched/null/absent origins, and bind handshakes to a CSRF token.`

	ModuleConfirmation = "Confirmed when a WebSocket upgrade succeeds with a malicious, null, subdomain, or missing Origin header"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "session", "moderate"}
)
