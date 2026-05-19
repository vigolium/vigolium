package mcp_server_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-server-probe"
	ModuleName  = "MCP Server Probe"
	ModuleShort = "Probes for exposed MCP servers, enumerates tools, and attempts unauthenticated invocation"
)

var (
	ModuleDesc = `## Description
Actively probes for Model Context Protocol (MCP) server endpoints on the target host.
Supports both Streamable HTTP and legacy SSE transports. On discovery, enumerates
available tools via tools/list and attempts invocation with sample data via tools/call.

## Scanning Phases
1. **Discovery**: Sends JSON-RPC initialize requests to known MCP paths (/mcp, /sse, /messages, /rpc, /api/mcp, /v1/mcp) using both Streamable HTTP (POST) and legacy SSE (GET) transports
2. **Enumeration**: On successful handshake, sends tools/list to enumerate available tools
3. **Invocation**: For each discovered tool, parses inputSchema and generates type-appropriate sample values (string, number, boolean, datetime, etc.), then calls via tools/call

## Findings
- Info: MCP endpoint responds to initialize handshake
- Medium: Unauthenticated tools/list succeeds (tools enumerable)
- High: Unauthenticated tools/call succeeds (tools callable without auth)

## References
- https://modelcontextprotocol.io/specification/2025-11-25
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports`

	ModuleConfirmation = "Confirmed when target responds with valid JSON-RPC 2.0 to MCP initialize request, tools are enumerable, or tools are callable without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "moderate"}
)
