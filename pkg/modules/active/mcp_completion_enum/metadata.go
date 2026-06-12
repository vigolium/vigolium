package mcp_completion_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-completion-enum"
	ModuleName  = "MCP Completion/Complete Enumeration"
	ModuleShort = "Uses MCP completion/complete to leak valid resource URIs and prompt argument values"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server answers unauthenticated completion/complete autocomplete queries by returning the full set of valid values for its prompt arguments and resource-template URI placeholders. This turns an IDE convenience feature into an enumeration oracle that leaks data the server treats as valid input, such as usernames, identifiers, file paths, or resource names.

**How it's exploited:** An attacker initializes a session and sends empty-prefix completion/complete requests against each prompt argument and template placeholder; the server replies with the enumerable value lists verbatim. Those values map out the server's resources and accepted inputs and seed direct follow-on access via resources/read (URI placeholders) and prompts/get, expanding the attack surface and exposing data meant to stay private.

**Fix:** Require authentication for completion/complete and avoid returning sensitive or enumerable value sets; restrict completions to non-sensitive hints or disable the capability where it leaks private data.`

	ModuleConfirmation = "Confirmed when completion/complete returns at least one value (the server is willing to disclose its valid value set without authentication)"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "info-disclosure", "enumeration", "light"}
)
