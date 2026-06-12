package mcp_session_checks

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-session-checks"
	ModuleName  = "MCP Session Hardening Checks"
	ModuleShort = "Tests Mcp-Session-Id entropy, attacker-supplied SID acceptance (fixation), and post-handshake reuse"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server mishandles its Mcp-Session-Id session lifecycle. The scanner found one or more of three weaknesses: session IDs that are short or low-entropy and therefore guessable; tools/list answered with no session at all (anonymous enumeration); or the server honouring an attacker-supplied Mcp-Session-Id during initialize (session fixation). Weak session handling lets an unauthenticated or unauthorized party reach MCP tools that should be gated behind a valid session.

**How it's exploited:** An attacker who can guess or brute-force a short session ID can hijack another client's MCP session; with anonymous enumeration they list and invoke server tools without any session; with fixation they pin a known Mcp-Session-Id, lure a victim onto it, and then ride the victim's authenticated session. Any of these exposes the tools, data, and downstream actions the MCP server offers.

**Fix:** Issue session IDs that are long and high-entropy, generate them server-side only (reject and ignore client-supplied Mcp-Session-Id values), and require a valid, authenticated session before answering tools/list or any tool call.`

	ModuleConfirmation = "Confirmed when sampled session IDs are short / low entropy, or the server accepts an attacker-supplied session ID, or tools/list succeeds without a session"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "session", "auth-bypass", "moderate"}
)
