package mcp_prompt_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-prompt-fuzz"
	ModuleName  = "MCP Prompt Argument Fuzzer"
	ModuleShort = "Fuzzes MCP prompts/get arguments for SSTI, command injection, and reflective prompt injection"
)

var (
	ModuleDesc = `**What it means:** An MCP (Model Context Protocol) server interpolates a prompts/get argument unsafely into a template engine, shell command, or text fed to a downstream LLM, processing it as code rather than inert data.

**How it's exploited:** An attacker crafts an argument to run template expressions, execute OS commands on the host, or smuggle instructions the downstream LLM obeys - yielding code execution, data exfiltration, or model hijacking.

**Fix:** Treat MCP prompt arguments as untrusted: never pass them to a shell or template evaluator, use parameterized rendering with strict escaping, and sanitize text before it reaches a model.`

	ModuleConfirmation = "Confirmed when SSTI evaluates the math marker, when the response delays for the sleep payload, or when the unique sentinel is echoed in the prompt result"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "ssti", "rce", "prompt-injection", "moderate"}
)
