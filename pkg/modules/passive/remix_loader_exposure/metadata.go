package remix_loader_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "remix-loader-exposure"
	ModuleName  = "Remix Loader Exposure"
	ModuleShort = "Detects sensitive data leaked through Remix loader data and context"
)

var (
	ModuleDesc = `**What it means:** A Remix application embeds sensitive data in server-rendered HTML through its loader state (window.__remixContext or inline loaderData blobs). The scanner found values resembling secrets: API keys, admin flags, emails, password hashes, database connection strings, or AWS access keys, sent to every visitor in plain text.

**How it's exploited:** An attacker views the page source and reads the leaked values directly. Leaked API keys, database URLs, or AWS credentials can be reused against backend services.

**Fix:** Return only the fields each route needs from loaders, and never include secrets, credentials, or internal details in client-sent loader data.`

	ModuleConfirmation = "Confirmed when sensitive data patterns are found in Remix loader data or context"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
