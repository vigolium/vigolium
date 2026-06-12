package ws_cswsh

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-cswsh"
	ModuleName  = "WebSocket CSWSH"
	ModuleShort = "Tests for Cross-Site WebSocket Hijacking via insufficient origin validation"
)

var (
	ModuleDesc = `**What it means:** A WebSocket endpoint completed a genuine upgrade handshake (101 Switching Protocols with Upgrade: websocket and Sec-WebSocket-Accept) when the request carried an attacker-controlled, null, spoofed-subdomain, or entirely missing Origin header. The server does not validate where WebSocket connections originate, exposing it to Cross-Site WebSocket Hijacking (CSWSH). Because WebSocket handshakes ride on the victim's cookies but are not protected by the same-origin policy or CSRF tokens, this is effectively CSRF for the WebSocket channel.

**How it's exploited:** An attacker hosts a malicious page that, when a logged-in victim visits it, silently opens a WebSocket back to the vulnerable endpoint. The victim's browser attaches their session cookies, so the connection is authenticated as the victim; the attacker's script can then read pushed data and send messages over that channel, leading to data theft or actions performed as the victim.

**Fix:** Validate the Origin header against an allowlist of trusted origins during the WebSocket handshake and reject mismatched, null, or absent origins, and bind handshakes to a CSRF token.`

	ModuleConfirmation = "Confirmed when a WebSocket upgrade succeeds with a malicious, null, subdomain, or missing Origin header"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "session", "moderate"}
)
