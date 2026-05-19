package mcp_description_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-description-injection"
	ModuleName  = "MCP Tool/Prompt Description Injection"
	ModuleShort = "Detects prompt-injection imperatives, bidi/zero-width unicode, and base64 payloads inside MCP tool/prompt descriptions"
)

var (
	ModuleDesc = `## Description
The descriptions of MCP tools, prompts, and resources are normally rendered
verbatim into a downstream LLM's context. A malicious or compromised MCP
server can use these strings as a free side-channel into the agent: encode
imperative-style instructions, hide instructions in bidi/zero-width unicode,
or embed base64 payloads.

This module passively scans ` + "`tools/list`" + `, ` + "`prompts/list`" + `, and
` + "`resources/list`" + ` responses (or any MCP-shaped response that contains a
` + "`description`" + ` field) for these markers.

## References
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- https://simonwillison.net/2024/Mar/13/prompt-injection-attacks-against-mcp-servers/`

	ModuleConfirmation = "Confirmed when an MCP description contains direct LLM imperatives, bidi-control or zero-width unicode, or a base64 blob that decodes to ASCII instructions"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "prompt-injection", "supply-chain", "light"}
)
