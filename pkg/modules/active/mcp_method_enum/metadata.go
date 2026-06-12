package mcp_method_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-method-enum"
	ModuleName  = "MCP JSON-RPC Method Enumeration"
	ModuleShort = "Wordlist-based enumeration of undocumented JSON-RPC methods on MCP servers"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server responds to undocumented JSON-RPC methods that are not part of its published interface, such as debug, admin, internal, and system operations. These hidden methods often sit outside the auth and tooling controls applied to documented endpoints, expanding the server's real attack surface.

**How it's exploited:** After completing the MCP initialize handshake, the scanner sends a short wordlist of plausible method names (for example debug/info, admin/users, system/exec, sampling/createMessage) and flags any that return a JSON-RPC result, or are recognised but rejected with an error code other than the standard -32601 method-not-found. An attacker uses the same enumeration to map maintenance and admin functionality, then probes the reachable methods for information disclosure, privileged actions, or further exploitation.

**Fix:** Remove or properly authenticate undocumented debug, admin, and internal JSON-RPC methods, and return -32601 for any method not meant to be publicly callable.`

	ModuleConfirmation = "Confirmed when the server returns a JSON-RPC result for an undocumented method, or an error other than -32601"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "enumeration", "info-disclosure", "moderate"}
)
