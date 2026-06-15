package mcp_batch_abuse

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-batch-abuse"
	ModuleName  = "MCP JSON-RPC Batch Abuse"
	ModuleShort = "Tests JSON-RPC batch handling: smuggled tools/call inside an initialize batch"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server applies its session gate per-request inside a JSON-RPC batch rather than to the batch as a whole, so an array bundling initialize with a sensitive method runs in full with no session, exposing the tool surface to unauthenticated callers.

**How it's exploited:** An attacker POSTs a batch of initialize plus tools/call with no Mcp-Session-Id header; the smuggled method returns a result alongside initialize, leaking tools and invoking privileged operations.

**Fix:** Validate the MCP session before processing any method, applying that gate to every batch entry so unestablished sessions cannot reach tools/call.`

	ModuleConfirmation = "Confirmed when a batched JSON-RPC array bypasses the per-request session gate, returning a result for tools/list or tools/call without a real session"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "auth-bypass", "moderate"}
)
