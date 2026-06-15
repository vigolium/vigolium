package sensitive_api_fields_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-api-fields-detect"
	ModuleName  = "Sensitive API Fields Detect"
	ModuleShort = "Flags JSON API responses containing sensitive field names like passwords, API keys, and PII"
)

var (
	ModuleDesc = `**What it means:** A JSON API response contains field names tied to sensitive data (password, secret, api_key, access_token, private_key, ssn, credit_card). APIs often over-share by serializing whole backend objects, leaking credentials or PII to clients. Names are matched passively, so each hit needs review.

**How it's exploited:** An attacker who reaches the endpoint or intercepts a response harvests the values: stolen keys and tokens enable account takeover, while SSN and card fields enable fraud. This is classic excessive data exposure.

**Fix:** Restrict responses to only the fields each caller is authorized to see, removing credentials and PII unless required.`

	ModuleConfirmation = "Confirmed when JSON response body contains sensitive field names"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"api", "info-disclosure", "light"}
)
