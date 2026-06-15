package mcp_origin_rebinding

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-origin-rebinding"
	ModuleName  = "MCP Origin / DNS-Rebinding Check"
	ModuleShort = "Verifies that an MCP server enforces Origin validation on streamable HTTP transports"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server over streamable HTTP accepted an initialize handshake carrying a foreign Origin header (https://attacker.example) instead of rejecting it. The spec requires Origin validation, especially for localhost-bound servers; missing it makes the server a DNS-rebinding sink.

**How it's exploited:** An attacker lures the victim to a page whose domain rebinds via DNS to the MCP host; the browser then issues cross-origin requests the server answers, letting the attacker invoke its tools and read local data.

**Fix:** Enforce strict Origin allow-listing on MCP HTTP transports and bind local servers to loopback only.`

	ModuleConfirmation = "Confirmed when an initialize request carrying a foreign Origin succeeds (HTTP 2xx + valid JSON-RPC result) without being rejected by the server"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "dns-rebinding", "origin", "moderate"}
)
