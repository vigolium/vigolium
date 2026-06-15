package mcp_resource_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-resource-fuzz"
	ModuleName  = "MCP Resource URI Fuzzer"
	ModuleShort = "Probes MCP resources/read with file://, gopher://, AWS metadata, and path-traversal payloads"
)

var (
	ModuleDesc = `**What it means:** This MCP (Model Context Protocol) server lets a client control which URI resources/read dereferences without restricting scheme or path, reading attacker-chosen local files (file:///etc/passwd, traversal) or arbitrary URLs - a server-side file-read and request-forgery flaw.

**How it's exploited:** An attacker (or prompt-injected agent) supplies a malicious URI to resources/read, reading /etc/passwd or secrets, or fetching cloud-metadata (169.254.169.254) to harvest credentials and pivot inward. Confirmed by file-content markers absent from the baseline or an OAST callback.

**Fix:** Allowlist the schemes and paths resources/read may dereference, reject file:// and traversal sequences, and block internal and metadata addresses.`

	ModuleConfirmation = "Confirmed when the resources/read response contains file-content markers absent from the baseline, or when the OAST provider records a callback for an injected URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "lfi", "ssrf", "path-traversal", "moderate"}
)
