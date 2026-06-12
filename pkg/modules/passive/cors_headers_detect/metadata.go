package cors_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-headers-detect"
	ModuleName  = "CORS Headers Detect"
	ModuleShort = "Passively detects permissive CORS headers in responses"
)

var (
	ModuleDesc = `**What it means:** The response returns a permissive Cross-Origin Resource Sharing (CORS) policy in its Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers. This was found passively, by reading the headers already returned, and flags risky combinations: a wildcard origin (*), the special null origin, credentials enabled alongside a wildcard, or credentials enabled for a specific origin. Such policies relax the browser same-origin protections that normally stop other websites from reading a response.
**How it's exploited:** A malicious website a victim visits can use JavaScript to send cross-origin requests to this endpoint and read the responses. When credentials are also allowed, those requests ride the victim's existing cookies or auth tokens, letting the attacker pull back private data, account details, or anti-CSRF tokens from authenticated pages. The null-origin and wildcard-with-credentials cases are the most dangerous because they trust any caller.
**Fix:** Reflect only an explicit allow-list of trusted origins, never use a wildcard or null origin together with Access-Control-Allow-Credentials, and omit CORS headers entirely on endpoints that do not need cross-origin access.`

	ModuleConfirmation = "Confirmed when response contains permissive CORS headers such as wildcard origin or credentials enabled"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "light"}
)
