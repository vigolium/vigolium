package client_path_traversal_confirm

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-path-traversal-confirm"
	ModuleName  = "Client-Side Path Traversal Confirm"
	ModuleShort = "Browser-confirms that a URL-controlled value escapes a client-side request path prefix"
)

var (
	ModuleDesc = `**What it means:** A URL-controlled value (location.hash/search) is concatenated into a client-side request path. This module drives a real browser to prove that a ../ segment in that value normalizes out of the intended path prefix, steering the page's own request to a different endpoint — a confirmed Client-Side Path Traversal (CSPT).

**How it's exploited:** A victim opens an attacker-crafted link; the page's authenticated fetch/XHR is redirected to an unintended endpoint, enabling data reads or state-changing calls under the victim's session.

**Fix:** Encode or allowlist path segments; never concatenate location data into request paths; resolve and validate paths server-side.`

	ModuleConfirmation = "Browser-confirmed when a ../ payload in the URL source escapes the request-path prefix across two distinct canaries while a benign control stays under the prefix"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"cspt", "dom", "browser", "heavy"}
)
