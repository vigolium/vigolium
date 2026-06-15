package mcp_session_checks

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-session-checks"
	ModuleName  = "MCP Session Hardening Checks"
	ModuleShort = "Tests Mcp-Session-Id entropy, attacker-supplied SID acceptance (fixation), and post-handshake reuse"
)

var (
	ModuleDesc = `**What it means:** This MCP (Model Context Protocol) server mishandles its Mcp-Session-Id lifecycle: short or low-entropy guessable IDs; tools/list answered with no session (anonymous enumeration); or honouring an attacker-supplied ID during initialize (fixation). Weak handling lets an unauthorized party reach gated tools.

**How it's exploited:** An attacker guesses a short ID to hijack a session, enumerates and invokes tools with no session, or pins a known ID, lures a victim onto it, and rides their session.

**Fix:** Issue long, high-entropy session IDs server-side only (reject client-supplied values), and require a valid authenticated session before answering tools/list or any tool call.`

	ModuleConfirmation = "Confirmed when sampled session IDs are short / low entropy, or the server accepts an attacker-supplied session ID, or tools/list succeeds without a session"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "session", "auth-bypass", "moderate"}
)
