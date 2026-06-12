package csrf_verify

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csrf-verify"
	ModuleName  = "CSRF Token Verification"
	ModuleShort = "Verifies CSRF token enforcement by removing, emptying, or randomizing tokens"
)

var (
	ModuleDesc = `**What it means:** A state-changing request (POST, PUT, DELETE, or PATCH) carried a CSRF token, but the server still processed the request after the scanner removed the token, emptied it, or replaced it with a random value. This means the anti-CSRF token is present but not actually enforced, leaving the action protected by it open to cross-site request forgery.

**How it's exploited:** An attacker hosts a malicious page that auto-submits a forged request to this endpoint while the victim is logged in. Because the server ignores the token, the request succeeds with the victim's session and the attacker can trigger sensitive actions (changing settings, making purchases, transferring funds, modifying account data) without the victim's consent. The finding is confirmed only when the mutated-token response matches the valid-token baseline, proving the token was truly bypassed rather than soft-rejected.

**Fix:** Reject any state-changing request whose CSRF token is missing, empty, or does not match the per-session expected value, and pair it with SameSite cookies.`

	ModuleConfirmation = "Confirmed when the server accepts a request with a removed, emptied, or randomized CSRF token"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"csrf", "audit", "moderate"}
)
