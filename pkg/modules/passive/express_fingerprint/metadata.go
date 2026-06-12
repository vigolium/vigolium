package express_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-fingerprint"
	ModuleName  = "Express/NestJS Fingerprint"
	ModuleShort = "Identifies Express.js and NestJS applications via response headers and error body patterns"
)

var (
	ModuleDesc = `**What it means:** This passive check fingerprints the server as an Express.js or NestJS (Node.js) application from response artifacts: an X-Powered-By: Express header, the default NestJS JSON error shape (statusCode, message, error) on 4xx/5xx responses, a connect.sid session cookie, or Express's default weak ETag format. It is an informational disclosure, not a vulnerability on its own, but unnecessary technology disclosure narrows an attacker's reconnaissance.
**How it's exploited:** An attacker uses the confirmed framework to focus testing on Express/NestJS-specific weaknesses, look up CVEs and known misconfigurations for the stack, and tailor payloads (for example prototype pollution, middleware bypasses, or session-handling flaws) instead of probing blindly. The connect.sid cookie additionally signals where session state lives.
**Fix:** Remove or override the X-Powered-By header (app.disable('x-powered-by') or helmet), rename the session cookie, and return generic error responses so the framework is not advertised.`

	ModuleConfirmation = "Confirmed when Express or NestJS-specific headers, cookies, or error body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"express", "nodejs", "fingerprint", "light"}
)
