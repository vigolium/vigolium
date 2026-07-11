package mcp_completion_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-completion-enum"
	ModuleName  = "MCP Completion/Complete Enumeration"
	ModuleShort = "Uses MCP completion/complete to leak valid resource URIs and prompt argument values"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server answers unauthenticated completion/complete queries by returning the full set of valid values for its prompt arguments and resource-template placeholders, turning autocomplete into an enumeration oracle that leaks usernames, identifiers, or file paths.

**How it's exploited:** An attacker initializes a session and sends empty-prefix completion/complete requests against each argument and placeholder; the server replies with the value lists verbatim, seeding follow-on access via resources/read and prompts/get.

**Fix:** Require authentication for completion/complete and avoid returning sensitive value sets; restrict completions to non-sensitive hints or disable the capability where it leaks private data.`

	ModuleConfirmation = "Observation when completion/complete returns ordinary values; candidate only for identity, credential, or sensitive-path shapes, without inferring anonymous access or downstream authorization impact"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "info-disclosure", "enumeration", "light"}
)
