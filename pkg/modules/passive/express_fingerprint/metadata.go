package express_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-fingerprint"
	ModuleName  = "Express/NestJS Fingerprint"
	ModuleShort = "Identifies Express.js and NestJS applications via response headers and error body patterns"
)

var (
	ModuleDesc = `**What it means:** This passive check fingerprints the server as Express.js or NestJS (Node.js) from response artifacts: an X-Powered-By: Express header, the default NestJS JSON error shape (statusCode, message, error), or a connect.sid session cookie. Informational technology disclosure, not a vulnerability itself.

**How it's exploited:** An attacker uses the confirmed framework to look up stack CVEs and misconfigurations and tailor payloads (prototype pollution, middleware bypasses, session flaws) instead of probing blindly. The connect.sid cookie signals where session state lives.

**Fix:** Remove or override X-Powered-By (app.disable('x-powered-by') or helmet), rename the session cookie, and return generic error responses.`

	ModuleConfirmation = "Confirmed when Express or NestJS-specific headers, cookies, or error body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"express", "nodejs", "fingerprint", "light"}
)
