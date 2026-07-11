package mcp_server_probe

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-server-probe"
	ModuleName  = "MCP Server Probe"
	ModuleShort = "Probes for exposed MCP servers, enumerates tools, and attempts unauthenticated invocation"
)

var (
	ModuleDesc = `**What it means:** Credential-free probing found an MCP endpoint, catalog, or callable non-state-changing tool. Discovery and enumeration are observations; successful benign invocation is a candidate. A private credential returned by a tool is a confirmed data leak.

**How it's exploited:** An attacker completes initialize, calls tools/list to map every tool, resource, and prompt, then calls tools/call to run them - reading internal files, querying databases, or triggering gated actions without logging in.

**Fix:** Require authentication and authorization on the MCP endpoint and do not expose it to untrusted networks.`

	ModuleConfirmation = "Observation for credential-free discovery/enumeration, candidate for successful benign invocation, and confirmed finding only when a private credential is returned; public identifiers are excluded"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "api-security", "misconfiguration", "moderate"}
)
