package idor_params_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "passive-idor-params-detect"
	ModuleName  = "IDOR Parameter Detection"
	ModuleShort = "Detects parameters that may reference object identifiers (IDOR/BOLA triage)"
)

var (
	ModuleDesc = `## Description
Passively identifies HTTP parameters whose names and values suggest they reference
object identifiers, providing triage signals for potential IDOR (Insecure Direct
Object Reference) and BOLA (Broken Object Level Authorization) vulnerabilities.

The module classifies parameter names (e.g. user_id, account_id) and values
(sequential integers, UUIDs, structured codes) to compute a confidence score.
Path parameters following resource nouns (e.g. /users/123) receive additional weight.

When JSON responses are present, the module also flags excessive data exposure by
detecting sensitive field names (password_hash, ssn, is_admin, etc.).

## Notes
- Informational finding: flags endpoints for further active testing (Layer 2+)
- Covers OWASP API1:2023 (BOLA) and API3:2023 (BOPLA) triage
- Does not send additional requests — purely passive analysis
- Deduplicates by host + normalized path pattern + parameter name + type

## References
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cwe.mitre.org/data/definitions/639.html`

	ModuleConfirmation = "Indicated when a request parameter has a high-signal identifier name combined with a predictable value format, or when a JSON response exposes sensitive internal fields"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"idor", "authentication", "light"}
)
