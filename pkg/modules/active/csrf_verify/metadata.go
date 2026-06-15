package csrf_verify

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-verify"
	ModuleName  = "CSRF Token Verification"
	ModuleShort = "Verifies CSRF token enforcement by removing, emptying, or randomizing tokens"
)

var (
	ModuleDesc = `**What it means:** A state-changing request (POST, PUT, DELETE) carried a CSRF token, but the server still processed it after the scanner removed, emptied, or randomized it. The token is present but not enforced, leaving the action open to cross-site request forgery.

**How it's exploited:** An attacker hosts a page that auto-submits a forged request while the victim is logged in. The server ignores the token, so it runs with the victim's session, triggering actions like settings changes or fund transfers.

**Fix:** Reject any state-changing request whose CSRF token is missing, empty, or invalid, and add SameSite cookies.`

	ModuleConfirmation = "Confirmed when the server accepts a request with a removed, emptied, or randomized CSRF token"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "audit", "moderate"}
)
