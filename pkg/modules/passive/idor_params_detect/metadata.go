package idor_params_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "idor-params-detect"
	ModuleName  = "IDOR Parameter Detection"
	ModuleShort = "Detects parameters that may reference object identifiers (IDOR/BOLA triage)"
)

var (
	ModuleDesc = `**What it means:** This is an informational triage finding, not a confirmed vulnerability. The scanner passively spotted a request parameter that looks like a direct object identifier (an ID-style name such as user_id or account_id carrying a predictable value like a sequential integer, UUID, or structured code, often after a resource noun like /users/123), or a JSON response that exposes sensitive field names (password_hash, ssn, is_admin, and similar). Such endpoints are common locations for IDOR / BOLA (Broken Object Level Authorization) and BOPLA (excessive property exposure) flaws.

**How it's exploited:** No request was sent and authorization was not tested here, so exploitability is unconfirmed. The disclosed parameter and value shape map attack surface for follow-up testing: an attacker would change the identifier to another user's value and check whether the response returns data belonging to that other object, indicating missing per-object access control.

**Fix:** Enforce per-object authorization on every request so a user can only access identifiers they own, and avoid returning sensitive internal fields in API responses.`

	ModuleConfirmation = "Indicated when a request parameter has a high-signal identifier name combined with a predictable value format, or when a JSON response exposes sensitive internal fields"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"idor", "authentication", "light"}
)
