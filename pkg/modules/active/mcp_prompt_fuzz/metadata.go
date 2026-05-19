package mcp_prompt_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-prompt-fuzz"
	ModuleName  = "MCP Prompt Argument Fuzzer"
	ModuleShort = "Fuzzes MCP prompts/get arguments for SSTI, command injection, and reflective prompt injection"
)

var (
	ModuleDesc = `## Description
Enumerates prompts via ` + "`prompts/list`" + ` and fuzzes each prompt's arguments
through ` + "`prompts/get`" + `. Prompts are a high-impact surface because their
output is normally fed verbatim back into a downstream LLM context, and the
server frequently interpolates argument values into shell commands or
template engines.

## Detections
- **SSTI**: ` + "`${7*7}`" + ` rendered as ` + "`49`" + ` in the prompt result.
- **Command injection**: time-based ` + "`sleep`" + ` payloads.
- **Reflective prompt injection**: a unique sentinel marker echoed back in
  any of the prompt result messages.

## References
- https://modelcontextprotocol.io/specification/2025-11-25/server/prompts
- https://owasp.org/www-project-top-10-for-large-language-model-applications/`

	ModuleConfirmation = "Confirmed when SSTI evaluates the math marker, when the response delays for the sleep payload, or when the unique sentinel is echoed in the prompt result"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "ssti", "rce", "prompt-injection", "moderate"}
)
