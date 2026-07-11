package mcp_dos_amplification

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-dos-amplification"
	ModuleName  = "MCP DoS Amplification"
	ModuleShort = "Tests JSON-RPC batch handling: an unbounded oversized ping batch processed with no size or rate limit"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server processes an unbounded JSON-RPC batch array with no size cap or rate limit, so one request forces it to run hundreds of operations at once — request amplification enabling resource exhaustion and denial of service.

**How it's exploited:** An attacker POSTs a single array of hundreds of method calls; the server answers every element, turning one small request into a large amount of work.

**Fix:** Cap batch array length, enforce per-client rate limits, and reject oversized batches before dispatching them.`

	ModuleConfirmation = "Differential candidate when a large harmless batch is processed after a small control; confirmation requires measured resource exhaustion or service degradation, and one request cannot prove absence of all limits"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "dos", "rate-limit", "moderate"}
)
