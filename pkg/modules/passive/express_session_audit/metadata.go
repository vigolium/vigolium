package express_session_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-session-audit"
	ModuleName  = "Express Session Audit"
	ModuleShort = "Audits Express.js session cookies for default naming, excessive expiry, and session proliferation"
)

var (
	ModuleDesc = `## Description
Audits Express.js session cookies for security issues beyond basic cookie attribute checks.
Detects default session names (connect.sid), excessive session expiry windows, and
session proliferation on anonymous or static requests.

## Notes
- Flags connect.sid default session name as a fingerprinting risk enabling framework identification
- Flags excessive Max-Age (>7 days / 604800 seconds) or very long Expires dates
- Detects session proliferation when session cookies are set on anonymous/static requests

## References
- https://expressjs.com/en/resources/middleware/session.html
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://owasp.org/www-community/controls/SecureCookieAttribute`

	ModuleConfirmation = "Confirmed when Express.js session cookies exhibit default naming, excessive expiry, or unnecessary proliferation"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"express", "nodejs", "session", "misconfiguration", "light"}
)
