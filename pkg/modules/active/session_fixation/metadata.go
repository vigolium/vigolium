package session_fixation

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "session-fixation"
	ModuleName  = "Session Fixation (permissive session)"
	ModuleShort = "Detects a permissive session mechanism that adopts an attacker-supplied session ID"
)

var (
	ModuleDesc = `**What it means:** The server uses a permissive session mechanism: it accepts a session identifier chosen by the client instead of issuing its own. An attacker can fix a victim's session ID, then hijack the session once the victim authenticates.

**How it's exploited:** The attacker plants a known session ID in the victim's browser (via a link/XSS/header). Because the server never regenerates it at login, the victim authenticates under the attacker-known ID and the attacker rides that session.

**Fix:** Reject client-supplied session IDs, generate them server-side, and always regenerate the session ID on login and privilege change.`

	ModuleConfirmation = "Confirmed when the server issues its own session cookie for a cookie-stripped request but then adopts (does not reissue) an attacker-supplied value for that same cookie — verified across two independent values"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"session", "auth", "session-fixation", "moderate"}
)
