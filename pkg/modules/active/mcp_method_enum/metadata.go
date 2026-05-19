package mcp_method_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-method-enum"
	ModuleName  = "MCP JSON-RPC Method Enumeration"
	ModuleShort = "Wordlist-based enumeration of undocumented JSON-RPC methods on MCP servers"
)

var (
	ModuleDesc = `## Description
Sends a wordlist of plausible undocumented JSON-RPC method names against an
MCP server (` + "`debug/*`" + `, ` + "`admin/*`" + `, ` + "`_internal/*`" + `, ` + "`system/*`" + `,
` + "`sampling/*`" + `, ` + "`logging/*`" + `, ` + "`roots/*`" + `, etc.) and reports any that
return a JSON-RPC ` + "`result`" + ` instead of a "method not found" error.

## Why this matters
The MCP spec deliberately keeps the method namespace open-ended. Real-world
servers ship developer/maintenance methods that bypass the documented auth
gates around ` + "`tools/call`" + ` etc. Enumerating these is high-leverage recon.

## Detection
A method is treated as exposed when the response is a JSON-RPC envelope with
either a non-empty ` + "`result`" + ` or a server-side error code that is not the
standard -32601 ("method not found").

## References
- https://www.jsonrpc.org/specification
- https://modelcontextprotocol.io/specification/2025-11-25`

	ModuleConfirmation = "Confirmed when the server returns a JSON-RPC result for an undocumented method, or an error other than -32601"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "enumeration", "info-disclosure", "moderate"}
)
