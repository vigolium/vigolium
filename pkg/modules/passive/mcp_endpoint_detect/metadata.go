package mcp_endpoint_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-endpoint-detect"
	ModuleName  = "MCP Endpoint Detect"
	ModuleShort = "Detects Model Context Protocol (MCP) server endpoints from HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server endpoint was identified on this host by its JSON-RPC 2.0 traffic, MCP method names, SSE event stream, Mcp-Session-Id header, or an exposed tools list. MCP servers expose AI tools, resources, and prompts that can read data or perform actions, so an unauthenticated or loosely scoped MCP endpoint reachable over the network widens the attack surface and may leak sensitive capabilities.

**How it's exploited:** Knowing an MCP endpoint and its protocol indicators lets an attacker map the exposed tools (the finding may list discovered tool names), probe each tool for missing authentication, command or path injection, or SSRF, and call privileged actions directly. Server info disclosed in responses also enables version-specific targeting of the MCP runtime.

**Fix:** Require authentication and strict authorization on the MCP endpoint, restrict it to trusted networks, and avoid disclosing server version and the full tool catalog to unauthenticated callers.`

	ModuleConfirmation = "Confirmed when response contains JSON-RPC 2.0 structure with MCP-specific method names or MCP transport indicators"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "light"}
)
