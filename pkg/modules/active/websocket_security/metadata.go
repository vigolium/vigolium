package websocket_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "websocket-security"
	ModuleName  = "WebSocket Security"
	ModuleShort = "Detects insecure WebSocket upgrade policies and missing origin validation"
)

var (
	ModuleDesc = `## Description
Detects WebSocket endpoints that accept upgrade requests without proper origin validation.
Tests whether the server enforces origin checks by sending upgrade requests with matching,
evil, and missing Origin headers.

## Notes
- Runs once per host+path with internal deduplication
- Sends up to 3 WebSocket upgrade probes per unique endpoint
- Low false-positive rate due to strict 101 status code matching

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- https://portswigger.net/web-security/websockets`

	ModuleConfirmation = "Confirmed when the server accepts a WebSocket upgrade request from an unauthorized or missing origin, indicating missing origin validation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "session", "light"}
)
