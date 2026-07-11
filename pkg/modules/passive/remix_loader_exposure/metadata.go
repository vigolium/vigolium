package remix_loader_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "remix-loader-exposure"
	ModuleName  = "Remix Loader Exposure"
	ModuleShort = "Detects sensitive data leaked through Remix loader data and context"
)

var (
	ModuleDesc = `**What it means:** Remix loader state contains security-relevant client data. Routine email/role data, public identifiers, internal addresses, and credential-free service URLs are observations. Private-token formats, password hashes, and password-bearing service URLs are candidates.

**How it's exploited:** An attacker views the page source and reads the leaked values directly. Leaked API keys, database URLs, or AWS credentials can be reused against backend services.

**Fix:** Return only the fields each route needs from loaders, and never include secrets, credentials, or internal details in client-sent loader data.`

	ModuleConfirmation = "Candidate for substantive private credentials in loader state; routine identity data and public identifiers remain observations until sensitivity and authorization are established"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
