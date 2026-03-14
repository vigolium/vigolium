package ws_cswsh

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-cswsh"
	ModuleName  = "WebSocket CSWSH"
	ModuleShort = "Tests for Cross-Site WebSocket Hijacking via insufficient origin validation"
)

var (
	ModuleDesc = `## Description
Tests for Cross-Site WebSocket Hijacking (CSWSH) by verifying whether WebSocket upgrade
endpoints properly validate the Origin header. An attacker can hijack a user's authenticated
WebSocket connection if the server does not enforce origin checks, allowing cross-origin
WebSocket handshakes to succeed.

## Notes
- Only tests endpoints that respond with 101 Switching Protocols to a well-formed WS upgrade.
- Tests four scenarios: evil external origin, null origin, subdomain spoofing, and missing
  Origin header.
- Deduplicates by host and path to avoid redundant checks.

## References
- https://christian-schneider.net/CrossSiteWebSocketHijacking.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking`

	ModuleConfirmation = "Confirmed when a WebSocket upgrade succeeds with a malicious, null, subdomain, or missing Origin header"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "session", "moderate"}
)
