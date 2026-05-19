package mcp_batch_abuse

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-batch-abuse"
	ModuleName  = "MCP JSON-RPC Batch Abuse"
	ModuleShort = "Tests JSON-RPC batch handling: smuggled tools/call inside an initialize batch"
)

var (
	ModuleDesc = `## Description
JSON-RPC 2.0 supports batched arrays of requests. Some MCP servers gate
sensitive methods (` + "`tools/call`" + `, ` + "`resources/read`" + `) behind a successful
` + "`initialize`" + ` but apply the gate per-request, so a batch that bundles
` + "`initialize`" + ` and ` + "`tools/call`" + ` together processes both even though the
session was never actually established.

This module sends a batched array containing ` + "`initialize`" + ` and one or more
` + "`tools/list`" + ` / ` + "`tools/call`" + ` requests (without an Mcp-Session-Id) and
flags the server when the smuggled requests succeed.

## References
- https://www.jsonrpc.org/specification
- https://modelcontextprotocol.io/specification/2025-11-25`

	ModuleConfirmation = "Confirmed when a batched JSON-RPC array bypasses the per-request session gate, returning a result for tools/list or tools/call without a real session"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "auth-bypass", "moderate"}
)
