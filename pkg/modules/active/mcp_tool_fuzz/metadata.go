package mcp_tool_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-tool-fuzz"
	ModuleName  = "MCP Tool Argument Fuzzer"
	ModuleShort = "Fuzzes arguments of every enumerable MCP tool for OS command injection, LFI, SSRF (OAST), and prompt injection"
)

var (
	ModuleDesc = `## Description
Enumerates every tool exposed by a Model Context Protocol (MCP) server via
` + "`tools/list`" + ` and, for each string-typed argument of each tool,
fuzzes the value with classic dynamic injection payloads:

- **OS command injection** (time-based ` + "`sleep`" + `)
- **Local file inclusion** (` + "`/etc/passwd`" + `, Windows ` + "`win.ini`" + ` markers)
- **SSRF** via OAST callbacks when an OAST provider is enabled
- **Reflective prompt injection** (a sentinel marker that signals if the
  response is rendered/echoed back into a downstream LLM context)

## How it works
1. Initialize MCP, list tools, build a benign baseline ` + "`tools/call`" + ` per tool.
2. For each top-level string argument of each tool, send mutated calls.
3. Detect:
   - command-injection: response duration >= 8 s on the sleep payload.
   - LFI: file-content markers in the tools/call result text.
   - SSRF: an OAST hit on the unique callback URL.
   - prompt-injection: the unique sentinel echoed verbatim in the response text.
4. Cap fan-out at 8 tools / 6 string args / 6 payloads per slot.

## Findings
- High: OS command injection in tool argument
- High: Local file inclusion in tool argument
- High: SSRF in tool argument (when OAST is enabled)
- Medium: Reflective prompt injection sink

## References
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://fenrisk.com/mcpwned-burp-suite-extension-mcp-servers`

	ModuleConfirmation = "Confirmed when a fuzzed tool argument triggers a measurable side-effect: response delay (cmd-i), file-content markers in the result (LFI), an OAST callback (SSRF), or echo of the sentinel marker (prompt injection)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "rce", "lfi", "ssrf", "injection", "moderate"}
)
