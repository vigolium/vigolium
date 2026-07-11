package authz_compare

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "authz-compare"
	ModuleName  = "Cross-Session Authorization Compare"
	ModuleShort = "Compares responses across authenticated sessions to detect IDOR/BOLA"
)

var (
	ModuleDesc = `**What it means:** The application fails to enforce object-level authorization: a request returning one user's data also returns data to a second authenticated session that lacks access. This is Broken Object Level Authorization (BOLA/IDOR).

**How it's exploited:** An attacker logged in as another user replays a victim's request referencing an account or document ID and receives the victim's identity-bearing object instead of a 401, 403, or the attacker's own personalized object.

**Fix:** Enforce per-object ownership checks server-side on every request, verifying the principal is authorized for the specific object rather than relying on unguessable IDs.`

	ModuleConfirmation = "Indicated when a compare session receives a successful response that retains the primary session's owner/account/user identity values for a self-scoped or object-referenced request"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"idor", "bola", "auth-bypass", "access-control", "api-security", "moderate"}
)
