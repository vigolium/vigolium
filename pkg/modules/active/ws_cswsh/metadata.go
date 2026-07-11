package ws_cswsh

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ws-cswsh"
	ModuleName  = "WebSocket CSWSH"
	ModuleShort = "Tests for Cross-Site WebSocket Hijacking via insufficient origin validation"
)

var (
	ModuleDesc = `**What it means:** A WebSocket accepted a missing, null, subdomain, or foreign Origin in fresh RFC-valid handshakes. Missing-Origin acceptance is an observation; foreign-Origin acceptance is a candidate. A finding also requires browser-sendable session credentials and a credential-free negative control.

**How it's exploited:** A malicious site opens the victim's authenticated socket and reads or sends messages with the victim's session.

**Fix:** Allowlist Origins, reject mismatched or null origins, and require a handshake CSRF token.`

	ModuleConfirmation = "Two fresh RFC-key-bound handshakes per origin; credentialed findings additionally require a browser-sendable session cookie and a repeated credential-free negative control"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "session", "moderate"}
)
