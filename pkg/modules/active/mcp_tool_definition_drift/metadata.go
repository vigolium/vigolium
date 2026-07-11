package mcp_tool_definition_drift

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-tool-definition-drift"
	ModuleName  = "MCP Tool Definition Drift"
	ModuleShort = "Detects MCP servers serving mutating, non-deterministic tool definitions (rug-pull risk)"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server serves non-deterministic tool definitions: repeated tools/list calls return different descriptions or input schemas for the same tool. Silently mutating an approved tool is the OWASP MCP "rug pull" risk.

**How it's exploited:** A client approves a benign tool; the server later swaps its description or schema to smuggle malicious instructions or parameters past human review. tools/list is polled repeatedly and any drift is flagged.

**Fix:** Pin and verify tool definitions after approval, and re-prompt the user whenever a description or schema changes between fetches.`

	ModuleConfirmation = "Observation for tool availability drift; differential candidate for canonicalized same-tool description/schema changes, with confirmation requiring an approved definition to be replaced without review"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"mcp", "rug-pull", "integrity", "moderate"}
)
