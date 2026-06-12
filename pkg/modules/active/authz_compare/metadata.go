package authz_compare

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "authz-compare"
	ModuleName  = "Cross-Session Authorization Compare"
	ModuleShort = "Compares responses across authenticated sessions to detect IDOR/BOLA"
)

var (
	ModuleDesc = `**What it means:** The application failed to enforce object-level authorization: a request that returns one user's data to the authenticated primary session also returns data to a second, different authenticated session that should not have access. This is a Broken Object Level Authorization (BOLA / IDOR) flaw, meaning one user can reach another user's records by simply replaying their request.

**How it's exploited:** An attacker logged in as a low-privilege or unrelated user replays a victim's request (for example a request referencing an account, order, or document ID) and receives a structurally similar 200 response containing different, user-specific data instead of a 401, 403, login redirect, or denial. By iterating identifiers they can read or act on data belonging to arbitrary other users, leading to mass data exposure across the tenant.

**Fix:** Enforce per-object ownership checks server-side on every request, verifying the authenticated principal is authorized for the specific object referenced rather than relying on the identifier being unguessable.`

	ModuleConfirmation = "Indicated when two different authenticated sessions receive structurally similar 200 responses with different content at the same endpoint, suggesting missing authorization enforcement"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"idor", "bola", "auth-bypass", "access-control", "api-security", "moderate"}
)
