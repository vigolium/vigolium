package mcp_resource_fuzz

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-resource-fuzz"
	ModuleName  = "MCP Resource URI Fuzzer"
	ModuleShort = "Probes MCP resources/read with file://, gopher://, AWS metadata, and path-traversal payloads"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server lets a client control which URI its resources/read operation dereferences, and it fails to restrict the scheme or path. The scanner confirmed it will read attacker-chosen targets such as local files (file:///etc/passwd, path traversal) or arbitrary network URLs. This is a server-side file-read and request-forgery flaw that exposes data the server can reach but the caller should not.

**How it's exploited:** An attacker (or a prompt-injected AI agent driving the MCP client) supplies a malicious URI to resources/read, reading local files like /etc/passwd or application secrets, or forcing the server to fetch internal/cloud-metadata endpoints (for example 169.254.169.254) to harvest credentials and pivot into the internal network. Confirmation here required real file-content markers absent from the baseline, or an out-of-band OAST callback, so the access is genuine, not a reflection.

**Fix:** Allowlist the URI schemes and paths resources/read may dereference, reject file:// and traversal sequences, and block requests to internal and metadata addresses.`

	ModuleConfirmation = "Confirmed when the resources/read response contains file-content markers absent from the baseline, or when the OAST provider records a callback for an injected URL"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "lfi", "ssrf", "path-traversal", "moderate"}
)
