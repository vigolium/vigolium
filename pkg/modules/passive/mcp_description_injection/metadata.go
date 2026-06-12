package mcp_description_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-description-injection"
	ModuleName  = "MCP Tool/Prompt Description Injection"
	ModuleShort = "Detects prompt-injection imperatives, bidi/zero-width unicode, and base64 payloads inside MCP tool/prompt descriptions"
)

var (
	ModuleDesc = `**What it means:** An MCP server is advertising tool, prompt, or resource descriptions that contain prompt-injection content: direct LLM imperatives (for example, ignore all previous instructions, reveal your system prompt), bidi-control or zero-width unicode hidden inside the text, or base64 blobs that decode to ASCII instructions. These descriptions are normally rendered verbatim into a downstream LLM agent's context as trusted text, so this is a tool-poisoning / supply-chain risk.
**How it's exploited:** A malicious or compromised MCP server uses the description field as a side-channel to inject commands into any agent that connects, steering the model to leak its system prompt, exfiltrate API keys or data, or invoke other tools without the operator noticing, since hidden unicode and base64 keep the payload invisible in normal UI review.
**Fix:** Do not connect to untrusted MCP servers, and sanitize or strip imperative phrasing, control/zero-width unicode, and encoded blobs from tool/prompt/resource descriptions before they reach the LLM context.`

	ModuleConfirmation = "Confirmed when an MCP description contains direct LLM imperatives, bidi-control or zero-width unicode, or a base64 blob that decodes to ASCII instructions"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "prompt-injection", "supply-chain", "light"}
)
