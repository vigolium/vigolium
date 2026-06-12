package mcp_tool_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-tool-fuzz"
	ModuleName  = "MCP Tool Argument Fuzzer"
	ModuleShort = "Fuzzes arguments of every enumerable MCP tool for OS command injection, LFI, SSRF (OAST), and prompt injection"
)

var (
	ModuleDesc = `**What it means:** A tool exposed by this Model Context Protocol (MCP) server passes one of its string arguments into a dangerous backend operation without validation. The scanner fuzzed each tool argument and observed a measurable side-effect, meaning untrusted input reaches an OS command, a file read, an outbound request, or a downstream LLM prompt.
**How it's exploited:** Anyone able to invoke the tool (often any client connected to the MCP server, including an AI agent acting on attacker-controlled content) can supply a crafted argument to run shell commands on the host, read local files such as /etc/passwd, force the server to make requests to internal systems (SSRF), or inject instructions that the server echoes into another LLM. Impact ranges from sensitive-file disclosure and internal network access to full server takeover via command execution.
**Fix:** Strictly validate and allowlist every tool argument, never pass argument values into shell commands, file paths, URLs, or LLM prompts, and run MCP tool handlers with least privilege.`

	ModuleConfirmation = "Confirmed when a fuzzed tool argument triggers a measurable side-effect: response delay (cmd-i), file-content markers in the result (LFI), an OAST callback (SSRF), or echo of the sentinel marker (prompt injection)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "rce", "lfi", "ssrf", "injection", "moderate"}
)
