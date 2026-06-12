package mcp_server_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-server-probe"
	ModuleName  = "MCP Server Probe"
	ModuleShort = "Probes for exposed MCP servers, enumerates tools, and attempts unauthenticated invocation"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server is exposed on this host and reachable over HTTP without authentication. MCP servers connect AI agents to backend tools, files, and data sources, so an internet-facing one is a powerful unauthenticated interface into the application's capabilities. Severity escalates with what the probe achieves: Info if the endpoint only completes the JSON-RPC initialize handshake, Medium if its tools/resources/prompts can be enumerated without credentials, and High if a tool was actually invoked without authentication.

**How it's exploited:** An attacker completes the initialize handshake on a known MCP path, calls tools/list to map every tool, resource, and prompt the server offers, then calls tools/call with crafted arguments to run those tools directly. Depending on what the tools do, this can read internal files, query databases, hit internal services, or trigger actions the AI agent was meant to gate, all without logging in.

**Fix:** Require authentication and authorization on the MCP endpoint and do not expose it to untrusted networks.`

	ModuleConfirmation = "Confirmed when target responds with valid JSON-RPC 2.0 to MCP initialize request, tools are enumerable, or tools are callable without authentication"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "moderate"}
)
