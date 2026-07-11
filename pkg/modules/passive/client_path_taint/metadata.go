package client_path_taint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-path-taint"
	ModuleName  = "Client-Side Path Traversal (taint candidate)"
	ModuleShort = "Reports a URL-controlled source flowing into a client-side request path"
)

var (
	ModuleDesc = `**What it means:** AST taint analysis traces a URL-controlled source (location.hash/search, URLSearchParams, document.URL) into a client-side request path (fetch, XMLHttpRequest.open, axios). When attacker-influenced data builds the request path, a crafted link can steer the browser to an unintended endpoint — Client-Side Path Traversal (CSPT).

**How it's exploited:** A victim opens an attacker-crafted URL; the tainted value injects ../ segments that redirect the page's authenticated call to another endpoint to read data or trigger actions.

**Fix:** Treat URL data as untrusted; encode path segments, allowlist values, and never concatenate location data into request paths.`

	ModuleConfirmation = "Reported when AST taint analysis traces a URL-controlled source into a client-side request-path sink (fetch/XHR/axios) within the same script"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cspt", "dom", "javascript", "light"}
)
