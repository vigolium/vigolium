package express_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-fingerprint"
	ModuleName  = "Express/NestJS Fingerprint"
	ModuleShort = "Identifies Express.js and NestJS applications via response headers and error body patterns"
)

var (
	ModuleDesc = `## Description
Passively identifies Express.js and NestJS applications by analyzing HTTP response
headers, cookies, and error body patterns. Detects X-Powered-By header set to Express,
NestJS default error shapes in JSON responses, connect.sid session cookie, and Express
default weak ETag format.

## Notes
- Passive only: does not send any HTTP requests
- Detects Express via X-Powered-By header
- Identifies NestJS by its default JSON error shape (statusCode, message, error)
- Recognizes connect.sid session cookie as Express session middleware
- Checks ETag header for Express default weak ETag format (W/"...")
- Deduplicates by host to avoid redundant processing

## References
- https://expressjs.com/en/api.html
- https://docs.nestjs.com/exception-filters
- https://github.com/expressjs/session`

	ModuleConfirmation = "Confirmed when Express or NestJS-specific headers, cookies, or error body patterns are detected in the response"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"express", "nodejs", "fingerprint", "light"}
)
