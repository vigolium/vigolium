package mcp_origin_rebinding

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-origin-rebinding"
	ModuleName  = "MCP Origin / DNS-Rebinding Check"
	ModuleShort = "Verifies that an MCP server enforces Origin validation on streamable HTTP transports"
)

var (
	ModuleDesc = `## Description
The MCP transport spec requires servers (especially those bound to localhost
or private interfaces) to validate the ` + "`Origin`" + ` header to prevent DNS
rebinding attacks from a victim's browser. This module verifies the policy
by re-issuing ` + "`initialize`" + ` with ` + "`Origin: https://attacker.example`" + `
and reports the server when it accepts the handshake unchanged.

## References
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#security-warning`

	ModuleConfirmation = "Confirmed when an initialize request carrying a foreign Origin succeeds (HTTP 2xx + valid JSON-RPC result) without being rejected by the server"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "dns-rebinding", "origin", "moderate"}
)
