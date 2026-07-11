package mcp_method_enum

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "mcp-method-enum"
	ModuleName  = "MCP JSON-RPC Method Enumeration"
	ModuleShort = "Wordlist-based enumeration of undocumented JSON-RPC methods on MCP servers"
)

var (
	ModuleDesc = `**What it means:** This Model Context Protocol (MCP) server responds to undocumented JSON-RPC methods outside its published interface, such as debug, admin, and system operations that often sit outside the auth controls on documented endpoints.

**How it's exploited:** After the initialize handshake, a wordlist of method names (debug/info, admin/users, system/exec) is sent, flagging any returning a result or rejected with an error other than -32601 method-not-found. An attacker uses this to probe for disclosure or privileged actions.

**Fix:** Remove or properly authenticate undocumented debug, admin, and internal methods, and return -32601 for any method not meant to be publicly callable.`

	ModuleConfirmation = "Candidate when a non-standard method returns a result distinct from a randomized unknown-method control; recognized-but-rejected methods are observations and no privileged impact is inferred"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"mcp", "enumeration", "info-disclosure", "moderate"}
)
