package mcp_prompt_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-prompt-fuzz"
	ModuleName  = "MCP Prompt Argument Fuzzer"
	ModuleShort = "Fuzzes MCP prompts/get arguments for SSTI, command injection, and reflective prompt injection"
)

var (
	ModuleDesc = `**What it means:** A Model Context Protocol (MCP) server exposes a prompt whose argument values are unsafely interpolated into a template engine, a shell command, or the text fed back to a downstream LLM. The scanner enumerated the server's prompts and confirmed that input fuzzed through prompts/get is processed as code or trusted instructions rather than inert data.

**How it's exploited:** An attacker supplies a crafted prompt argument to run server-side template expressions (a math marker rendering evaluated confirms template injection), execute operating-system commands on the MCP host (a sleep payload that delays the response confirms this), or smuggle adversarial instructions that the downstream LLM obeys (prompt injection). Depending on the sink this leads to remote code execution, data exfiltration, or hijacking the model's behavior and any tools it can call.

**Fix:** Treat all MCP prompt arguments as untrusted data: never pass them to a shell or template evaluator, use parameterized rendering with strict escaping, and sanitize argument text before it reaches a downstream model.`

	ModuleConfirmation = "Confirmed when SSTI evaluates the math marker, when the response delays for the sleep payload, or when the unique sentinel is echoed in the prompt result"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "ssti", "rce", "prompt-injection", "moderate"}
)
