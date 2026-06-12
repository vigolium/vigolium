package idor_guid

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-guid"
	ModuleName  = "IDOR GUID Predictability"
	ModuleShort = "Detects predictable GUID patterns like UUIDv1 with extractable timestamps"
)

var (
	ModuleDesc = `**What it means:** An object-reference parameter (an id, uuid, account_id, order_id, and similar) carries a predictable identifier, and the application served a different valid object when a guessed neighbor identifier was substituted. This is an Insecure Direct Object Reference: the endpoint trusts the identifier alone and does not verify the caller is authorized for that object, so other users' records can be reached by guessing IDs.

**How it's exploited:** The scanner confirmed predictability two ways. For UUIDv1 values it extracted the embedded timestamp, generated time-neighbor UUIDs, and replayed them; for numeric ids it incremented and decremented by one. A neighbor returned HTTP 200 with a substantial body that differed from the original, was not a login, SSO, or access-denied page, and held up against the endpoint's own per-request variation. An attacker can walk these identifiers to enumerate other accounts' records, leaking personal or business data at scale.

**Fix:** Enforce per-object authorization on every request and use unpredictable, non-sequential identifiers such as random UUIDv4 instead of UUIDv1 or auto-increment integers.`
	ModuleConfirmation = "Confirmed when a predicted neighbor identifier returns a 200 response that is a distinct application object — not a login/SSO challenge or access-denied page, and differing from the baseline by more than the endpoint's own per-request variation"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"idor", "auth-bypass", "moderate"}
)
