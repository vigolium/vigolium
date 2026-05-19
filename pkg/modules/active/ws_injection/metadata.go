package ws_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-injection"
	ModuleName  = "WebSocket Injection"
	ModuleShort = "Tests for injection vulnerabilities in parameters forwarded to WebSocket message processing"
)

var (
	ModuleDesc = `## Description
Tests for injection vulnerabilities (XSS, SQLi, command injection, template injection) in HTTP
parameters that are likely forwarded to WebSocket message processing contexts. The module targets
parameters with names commonly associated with WebSocket messaging (e.g., message, data, payload,
cmd) and sends crafted payloads to detect unvalidated input handling.

## Notes
- Only tests parameters whose names suggest WebSocket message processing involvement.
- Checks for reflected XSS payloads, SQL error messages, command output patterns, and template
  expression evaluation in responses.
- Uses insertion-point-level deduplication to avoid redundant checks.

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets
- https://portswigger.net/web-security/websockets`

	ModuleConfirmation = "Confirmed when an injected payload is reflected unencoded, triggers a SQL error, produces command output, or evaluates a template expression in the HTTP response"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "moderate"}
)
