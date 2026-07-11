package websocket_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "websocket-security"
	ModuleName  = "WebSocket Security"
	ModuleShort = "Detects insecure WebSocket upgrade policies and missing origin validation"
)

var (
	ModuleDesc = `**What it means:** This is the legacy alias for the canonical ws-cswsh implementation. It distinguishes reproduced WebSocket origin-policy behavior from a credential-dependent browser handshake and does not infer an authenticated session from a 101 response alone.

**Evidence tiers:** Missing Origin acceptance is an observation, arbitrary Origin acceptance is a candidate, and a finding requires a known browser-sendable session cookie plus rejection by the credential-free control. The default registry registers only ws-cswsh to avoid duplicate output.

**Fix:** Validate the Origin header on the upgrade, reject unexpected or missing origins, and bind the connection to a per-session CSRF-style token.`

	ModuleConfirmation = "Delegates to ws-cswsh, which uses fresh RFC-bound handshakes, repeated origin variants, and a credential-free negative control"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "session", "light"}
)
