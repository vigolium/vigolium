package mcp_endpoint_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-endpoint-detect"
	ModuleName  = "MCP Endpoint Detect"
	ModuleShort = "Detects Model Context Protocol (MCP) server endpoints from HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server endpoint was identified by its JSON-RPC 2.0 traffic, MCP method names, SSE stream, Mcp-Session-Id header, or exposed tools list. MCP servers expose AI tools that read data or perform actions, so an unauthenticated endpoint widens the attack surface.

**How it's exploited:** An attacker maps the exposed tools, probes each for missing authentication, command or path injection, or SSRF, and calls privileged actions directly. Disclosed server info enables version-specific targeting.

**Fix:** Require authentication and authorization on the endpoint, restrict it to trusted networks, and avoid disclosing server version and the tool catalog.`

	ModuleConfirmation = "Confirmed when response contains JSON-RPC 2.0 structure with MCP-specific method names or MCP transport indicators"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "light"}
)
