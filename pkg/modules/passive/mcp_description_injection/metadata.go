package mcp_description_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-description-injection"
	ModuleName  = "MCP Tool/Prompt Description Injection"
	ModuleShort = "Detects prompt-injection imperatives, bidi/zero-width unicode, and base64 payloads inside MCP tool/prompt descriptions"
)

var (
	ModuleDesc = `**What it means:** An MCP server advertises tool, prompt, or resource descriptions containing prompt-injection content: direct LLM imperatives, hidden bidi-control or zero-width unicode, or base64 blobs decoding to ASCII instructions. These render verbatim into a downstream LLM agent - a tool-poisoning risk.

**How it's exploited:** The description field injects commands into any connecting agent, steering it to leak its system prompt, exfiltrate keys or data, or invoke other tools - hidden unicode and base64 hide the payload from UI review.

**Fix:** Avoid untrusted MCP servers, and sanitize imperatives, control/zero-width unicode, and encoded blobs before descriptions reach the LLM context.`

	ModuleConfirmation = "Candidate for direct or decoded imperative payloads; obfuscation-only unicode remains an observation, and confirmation requires downstream model behavior or tool/data impact"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "prompt-injection", "supply-chain", "light"}
)
