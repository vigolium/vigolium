package sensitive_api_fields_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-api-fields-detect"
	ModuleName  = "Sensitive API Fields Detect"
	ModuleShort = "Flags JSON API responses containing sensitive field names like passwords, API keys, and PII"
)

var (
	ModuleDesc = `**What it means:** A JSON API response returned by the application contains field names associated with sensitive data, such as password, passwd, secret, api_key/apiKey, access_token/accessToken, private_key/privateKey, ssn, or credit_card/cardNumber. APIs often over-share by serializing entire backend objects, so these properties may be leaking credentials, secrets, or personal data (PII) to clients that should never receive them.

**How it's exploited:** An attacker who can reach this endpoint, or who intercepts a legitimate response, harvests the exposed values directly from the JSON: stolen passwords, API keys, and access tokens enable account takeover or lateral access to other services, while SSN and credit-card fields expose users to fraud and identity theft. This is a common form of excessive data exposure / broken object property-level authorization. This module only matches field names passively and does not verify the values are populated, so each hit should be reviewed manually.

**Fix:** Restrict API responses to only the fields each caller is authorized to see, removing credentials, secrets, and PII from serialized output unless explicitly required.`

	ModuleConfirmation = "Confirmed when JSON response body contains sensitive field names"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"api", "info-disclosure", "light"}
)
