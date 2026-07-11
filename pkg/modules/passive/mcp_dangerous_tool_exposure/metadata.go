package mcp_dangerous_tool_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-dangerous-tool-exposure"
	ModuleName  = "MCP Dangerous Tool Exposure"
	ModuleShort = "Inventories MCP tools whose names expose high-impact capabilities (code execution, file write/delete, outbound fetch, raw SQL, secret access)"
)

var (
	ModuleDesc = `**What it means:** This MCP server advertises tools whose names indicate high-impact capabilities — running commands, deleting files, fetching arbitrary URLs, executing raw SQL, or reading secrets. Over-scoped permissions widen the blast radius of any prompt-injection or missing-auth flaw.

**How it's exploited:** An attacker or prompt-injected agent invokes one directly: exec yields code execution, delete/write destroys files, fetch pivots via SSRF to cloud metadata, sql exposes the database, a secret tool leaks keys.

**Fix:** Least privilege — gate high-impact tools behind authentication and human approval, allowlist their targets, and never expose raw command, SQL, or file-write to unauthenticated callers.`

	ModuleConfirmation = "Observation when a parsed JSON-RPC tools/list advertises high-impact capability names; invocation, authorization, approval gates, and impact remain untested"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "excessive-permissions", "api-security", "light"}
)
