package remix_loader_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "remix-loader-exposure"
	ModuleName  = "Remix Loader Exposure"
	ModuleShort = "Detects sensitive data leaked through Remix loader data and context"
)

var (
	ModuleDesc = `**What it means:** A Remix application is embedding sensitive data in the server-rendered HTML through its loader state (window.__remixContext, window.__remixManifest, or inline loaderData script blobs). The scanner found values inside that state that look like secrets or internal details, such as API keys and tokens, admin or privilege flags, email addresses, password hashes, private/internal IP addresses, database connection strings, or AWS access keys. Anything in this state is delivered to every visitor's browser in plain text.

**How it's exploited:** An attacker simply views the page source or response body and reads the leaked values directly, with no special access or tooling. Leaked API keys, database URLs, or AWS credentials can be reused to access backend services; exposed emails or admin flags help enumerate users and target privileged accounts.

**Fix:** Return only the fields each route actually needs from loaders, and never include secrets, credentials, password hashes, or internal infrastructure details in loader data or context serialized to the client.`

	ModuleConfirmation = "Confirmed when sensitive data patterns are found in Remix loader data or context"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
