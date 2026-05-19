package mcp_session_checks

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-session-checks"
	ModuleName  = "MCP Session Hardening Checks"
	ModuleShort = "Tests Mcp-Session-Id entropy, attacker-supplied SID acceptance (fixation), and post-handshake reuse"
)

var (
	ModuleDesc = `## Description
Audits the lifecycle of the ` + "`Mcp-Session-Id`" + ` header issued by an MCP
server:

- **Entropy / predictability**: collects multiple session IDs and reports
  short or low-entropy values.
- **Fixation**: sends an ` + "`initialize`" + ` with an attacker-supplied
  ` + "`Mcp-Session-Id`" + ` header. If a follow-up ` + "`tools/list`" + ` succeeds
  using that exact value, the server is accepting client-provided SIDs.
- **No-Auth Tools List**: confirms whether ` + "`tools/list`" + ` works without
  any session at all (anonymous enumeration).

## References
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- OWASP ASVS 4.0 V3 Session Management`

	ModuleConfirmation = "Confirmed when sampled session IDs are short / low entropy, or the server accepts an attacker-supplied session ID, or tools/list succeeds without a session"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "session", "auth-bypass", "moderate"}
)
