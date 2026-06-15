package mcp_tool_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-tool-fuzz"
	ModuleName  = "MCP Tool Argument Fuzzer"
	ModuleShort = "Fuzzes arguments of every enumerable MCP tool for OS command injection, LFI, SSRF (OAST), and prompt injection"
)

var (
	ModuleDesc = `**What it means:** A tool on this MCP (Model Context Protocol) server passes a string argument into a dangerous backend operation without validation, so untrusted input reaches an OS command, file read, outbound request, or LLM prompt.

**How it's exploited:** Anyone able to invoke the tool crafts an argument to run shell commands, read files like /etc/passwd, force requests to internal systems (SSRF), or inject LLM instructions - from file disclosure to full server takeover.

**Fix:** Validate and allowlist every tool argument, never pass values into shell commands, file paths, URLs, or LLM prompts, and run handlers with least privilege.`

	ModuleConfirmation = "Confirmed when a fuzzed tool argument triggers a measurable side-effect: response delay (cmd-i), file-content markers in the result (LFI), an OAST callback (SSRF), or echo of the sentinel marker (prompt injection)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "rce", "lfi", "ssrf", "injection", "moderate"}
)
