package mcp_origin_rebinding

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-origin-rebinding"
	ModuleName  = "MCP Origin / DNS-Rebinding Check"
	ModuleShort = "Verifies that an MCP server enforces Origin validation on streamable HTTP transports"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server reachable over streamable HTTP accepted an initialize handshake that carried a foreign Origin header (https://attacker.example) instead of rejecting it. The MCP transport spec requires servers, especially those bound to localhost or a private interface, to validate Origin so that a web page in the victim's browser cannot talk to the server. Missing this check makes the server a DNS-rebinding sink.

**How it's exploited:** An attacker lures the victim to a malicious web page whose domain resolves (via DNS rebinding) to 127.0.0.1 or the MCP host. The victim's browser then issues cross-origin requests that the server answers, letting the attacker drive the MCP server, invoke its tools, and read or act on the user's local data and resources on their behalf.

**Fix:** Enforce strict Origin allow-listing on all MCP HTTP transports, rejecting any handshake whose Origin is not a trusted local value, and bind local servers to loopback only.`

	ModuleConfirmation = "Confirmed when an initialize request carrying a foreign Origin succeeds (HTTP 2xx + valid JSON-RPC result) without being rejected by the server"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "dns-rebinding", "origin", "moderate"}
)
