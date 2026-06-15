package mcp_server_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-server-probe"
	ModuleName  = "MCP Server Probe"
	ModuleShort = "Probes for exposed MCP servers, enumerates tools, and attempts unauthenticated invocation"
)

var (
	ModuleDesc = `**What it means:** An MCP (Model Context Protocol) server, which connects AI agents to backend tools, files, and data, is exposed over HTTP without authentication. Severity escalates: Info if only the JSON-RPC initialize handshake completes, Medium if tools enumerate, High if a tool was invoked unauthenticated.

**How it's exploited:** An attacker completes initialize, calls tools/list to map every tool, resource, and prompt, then calls tools/call to run them - reading internal files, querying databases, or triggering gated actions without logging in.

**Fix:** Require authentication and authorization on the MCP endpoint and do not expose it to untrusted networks.`

	ModuleConfirmation = "Confirmed when target responds with valid JSON-RPC 2.0 to MCP initialize request, tools are enumerable, or tools are callable without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "moderate"}
)
