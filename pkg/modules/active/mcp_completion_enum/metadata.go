package mcp_completion_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-completion-enum"
	ModuleName  = "MCP Completion/Complete Enumeration"
	ModuleShort = "Uses MCP completion/complete to leak valid resource URIs and prompt argument values"
)

var (
	ModuleDesc = `## Description
The MCP ` + "`completion/complete`" + ` primitive is intended for IDE-style argument
autocomplete, but in practice it is an enumeration oracle: empty/short
prefixes return back the full list of values the server considers valid for a
given resource URI placeholder or prompt argument.

This module sends a series of empty + short-prefix completion queries against
every resource template placeholder and every prompt argument and reports the
returned values verbatim. Use the output to seed exploitation in
` + "`resources/read`" + ` (URI placeholders) and ` + "`prompts/get`" + `.

## References
- https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion`

	ModuleConfirmation = "Confirmed when completion/complete returns at least one value (the server is willing to disclose its valid value set without authentication)"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "info-disclosure", "enumeration", "light"}
)
