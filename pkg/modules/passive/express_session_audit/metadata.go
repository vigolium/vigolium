package express_session_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-session-audit"
	ModuleName  = "Express Session Audit"
	ModuleShort = "Audits Express.js session cookies for default naming, excessive expiry, and session proliferation"
)

var (
	ModuleDesc = `**What it means:** This passive check inspects Set-Cookie headers and reports session-management hygiene issues in Express.js applications. It flags three things: the default connect.sid session cookie name, which reveals the Express/Connect framework; an excessive session lifetime (Max-Age over 7 days / 604800 seconds); and session cookies being set on static or anonymous GET requests (session proliferation). These are low-risk configuration and hardening weaknesses, not direct vulnerabilities on their own.

**How it's exploited:** The connect.sid name confirms the backend stack, letting an attacker focus on Express-specific weaknesses and known middleware issues. An over-long session lifetime widens the window in which a stolen or fixated session cookie stays valid, so a single token theft yields prolonged account access. Sessions issued to unauthenticated visitors can be abused to exhaust server-side session storage or aid session-fixation setups.

**Fix:** Rename the session cookie away from connect.sid, cap session Max-Age to a short window (ideally 7 days or less), and avoid creating sessions for static or anonymous requests.`

	ModuleConfirmation = "Confirmed when Express.js session cookies exhibit default naming, excessive expiry, or unnecessary proliferation"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "nodejs", "session", "misconfiguration", "light"}
)
