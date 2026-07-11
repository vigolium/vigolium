package session_fixation

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "session-fixation"
	ModuleName  = "Session Fixation (permissive session)"
	ModuleShort = "Detects a permissive session mechanism that adopts an attacker-supplied session ID"
)

var (
	ModuleDesc = `**What it means:** The server explicitly adopted a client-chosen session identifier. Adoption is a candidate; preservation through a successful authentication transition is a confirmed session-fixation finding.

**How it's exploited:** An attacker plants a known session ID in the victim's browser. If login does not regenerate it, the attacker can reuse the authenticated session.

**Fix:** Reject client-supplied session IDs, generate them server-side, and regenerate the session on login and privilege changes.`

	ModuleConfirmation = "Candidate when the server explicitly Set-Cookie's two attacker-chosen identifiers unchanged; confirmed only when that behavior occurs across a successful authentication transition"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"session", "auth", "session-fixation", "moderate"}
)
