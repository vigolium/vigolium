package cors_headers_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cors-headers-detect"
	ModuleName  = "CORS Headers Detect"
	ModuleShort = "Passively detects permissive CORS headers in responses"
)

var (
	ModuleDesc = `**What it means:** The response returns a permissive CORS policy - a wildcard (*) or null Access-Control-Allow-Origin, or credentials enabled alongside either - relaxing the same-origin protections that stop other sites reading a response.

**How it's exploited:** A malicious page the victim visits sends cross-origin requests here and reads the responses. With credentials allowed, requests ride the victim's cookies, exposing private data and anti-CSRF tokens. The null and wildcard-with-credentials cases are worst, trusting any caller.

**Fix:** Reflect only an explicit allow-list of trusted origins, never pair a wildcard or null origin with Access-Control-Allow-Credentials, and omit CORS headers where not needed.`

	ModuleConfirmation = "Confirmed when response contains permissive CORS headers such as wildcard origin or credentials enabled"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "light"}
)
