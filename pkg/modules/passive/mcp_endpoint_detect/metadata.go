package mcp_endpoint_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-endpoint-detect"
	ModuleName  = "MCP Endpoint Detect"
	ModuleShort = "Detects Model Context Protocol (MCP) server endpoints from HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects MCP (Model Context Protocol) server endpoints by analyzing HTTP
responses for JSON-RPC 2.0 structures with MCP-specific methods, SSE event streams,
and characteristic response headers.

## Notes
- Checks response bodies for JSON-RPC 2.0 messages with MCP methods (initialize, tools/list, tools/call)
- Detects SSE streams (text/event-stream) containing MCP event data
- Identifies MCP-related response headers (Mcp-Session-Id)
- Extracts server info and tool names when visible in response bodies
- One finding per host with all detected MCP indicators

## References
- https://modelcontextprotocol.io/specification/2025-11-25
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports`

	ModuleConfirmation = "Confirmed when response contains JSON-RPC 2.0 structure with MCP-specific method names or MCP transport indicators"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "light"}
)
