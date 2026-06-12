package cors_misconfiguration

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-misconfiguration"
	ModuleName  = "CORS Misconfiguration"
	ModuleShort = "Detects permissive CORS policies allowing unauthorized cross-origin access"
)

var (
	ModuleDesc = `**What it means:** The server returns a permissive Cross-Origin Resource Sharing (CORS) policy that lets origins outside the application read its responses. This module sends crafted Origin headers and confirms the server grants access by reflecting an attacker-chosen origin in Access-Control-Allow-Origin, allowing the null origin, pairing a wildcard with credentials, or accepting forged subdomain, prefix, suffix, port, or HTTP-scheme origins.

**How it's exploited:** An attacker hosts a malicious page that scripts an authenticated cross-origin request to the target. Because the server echoes or wrongly trusts the attacker's origin, the browser hands the response back to the attacker's JavaScript, leaking session-protected data such as profile details, API tokens, or CSRF tokens. The wildcard-with-credentials case signals broken CORS logic even where browsers block it.

**Fix:** Validate the Origin header against a strict server-side allowlist of exact trusted origins, never reflect arbitrary origins, never combine Access-Control-Allow-Origin wildcard with credentials, and reject the null origin.`

	ModuleConfirmation = "Confirmed when the server reflects a controlled Origin value in the Access-Control-Allow-Origin header, indicating permissive CORS policy"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "auth-bypass", "moderate"}
)
