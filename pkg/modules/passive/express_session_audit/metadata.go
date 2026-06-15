package express_session_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-session-audit"
	ModuleName  = "Express Session Audit"
	ModuleShort = "Audits Express.js session cookies for default naming, excessive expiry, and session proliferation"
)

var (
	ModuleDesc = `**What it means:** This passive check flags Express.js session hygiene issues in Set-Cookie headers: the default connect.sid name, an excessive Max-Age over 7 days, and sessions set on static or anonymous requests. Low-risk hardening weaknesses, not direct vulnerabilities.

**How it's exploited:** The connect.sid name confirms the backend stack. A long lifetime keeps a stolen or fixated cookie valid longer, so one theft yields prolonged access, and anonymous sessions aid storage exhaustion or fixation.

**Fix:** Rename the cookie away from connect.sid, cap Max-Age to 7 days or less, and avoid sessions on static or anonymous requests.`

	ModuleConfirmation = "Confirmed when Express.js session cookies exhibit default naming, excessive expiry, or unnecessary proliferation"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "nodejs", "session", "misconfiguration", "light"}
)
