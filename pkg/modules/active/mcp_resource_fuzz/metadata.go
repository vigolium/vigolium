package mcp_resource_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-resource-fuzz"
	ModuleName  = "MCP Resource URI Fuzzer"
	ModuleShort = "Probes MCP resources/read with file://, gopher://, AWS metadata, and path-traversal payloads"
)

var (
	ModuleDesc = `## Description
Enumerates MCP resources and resource-template URIs (` + "`resources/list`" + ` and
` + "`resources/templates/list`" + `) and exercises ` + "`resources/read`" + ` with
classic LFI / SSRF / path-traversal payloads. The MCP spec leaves the URI
schemes a server is willing to dereference unspecified, so misconfigured
servers happily read ` + "`file:///etc/passwd`" + `, ` + "`http://169.254.169.254/`" + `,
or ` + "`gopher://`" + ` URIs.

## How it works
1. Initialize the MCP server.
2. List resources and resource templates.
3. For each resource template, substitute placeholders with the payload (or
   send the payload as a bare URI when no template is available).
4. Detect LFI by file-content markers in the result text and SSRF via the
   OAST provider when enabled.

## Findings
- High: file content disclosed via resources/read
- High: SSRF confirmed via OAST callback

## References
- https://modelcontextprotocol.io/specification/2025-11-25/server/resources
- https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762`

	ModuleConfirmation = "Confirmed when the resources/read response contains file-content markers absent from the baseline, or when the OAST provider records a callback for an injected URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "lfi", "ssrf", "path-traversal", "moderate"}
)
