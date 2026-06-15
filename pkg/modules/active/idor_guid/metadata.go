package idor_guid

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-guid"
	ModuleName  = "IDOR GUID Predictability"
	ModuleShort = "Detects predictable GUID patterns like UUIDv1 with extractable timestamps"
)

var (
	ModuleDesc = `**What it means:** An object-reference parameter (id, uuid, account_id) carries a predictable identifier, and the app served a different valid object when a guessed neighbor was substituted - an Insecure Direct Object Reference trusting the identifier without checking authorization.

**How it's exploited:** For UUIDv1 the scanner extracted the embedded timestamp, generated time-neighbor UUIDs, and replayed them; for numeric ids it incremented by one. A neighbor returned a substantial 200 body differing from the original, so an attacker enumerates other accounts.

**Fix:** Enforce per-object authorization and use unpredictable, non-sequential identifiers such as random UUIDv4 instead of UUIDv1 or auto-increment IDs.`
	ModuleConfirmation = "Confirmed when a predicted neighbor identifier returns a 200 response that is a distinct application object — not a login/SSO challenge or access-denied page, and differing from the baseline by more than the endpoint's own per-request variation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
