package mcp_batch_abuse

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-batch-abuse"
	ModuleName  = "MCP JSON-RPC Batch Abuse"
	ModuleShort = "Tests JSON-RPC batch handling: smuggled tools/call inside an initialize batch"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server enforces its session/authentication gate per-request inside a JSON-RPC batch instead of for the batch as a whole, so a single array that bundles an initialize call with a sensitive method is processed in full even though no real session was ever established. This lets a caller reach MCP methods that should require a valid, authenticated session, exposing the server's tool and resource surface to unauthenticated clients.

**How it's exploited:** An attacker POSTs a batched JSON-RPC array containing initialize plus tools/list (or tools/call) with no Mcp-Session-Id header; the smuggled method returns a result alongside the initialize response, leaking the server's available tools and potentially allowing invocation of privileged tool/resource operations without ever holding a session.

**Fix:** Establish and validate the MCP session before processing any method, and apply that gate to every entry in a batch (or reject batched requests outright) so unestablished sessions cannot reach tools/call or resources/read.`

	ModuleConfirmation = "Confirmed when a batched JSON-RPC array bypasses the per-request session gate, returning a result for tools/list or tools/call without a real session"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "auth-bypass", "moderate"}
)
