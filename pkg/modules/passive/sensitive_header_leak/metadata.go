package sensitive_header_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-header-leak"
	ModuleName  = "Sensitive Data in Response Headers"
	ModuleShort = "Detects high-entropy / key-shaped values disclosed in custom response headers"
)

var (
	ModuleDesc = `**What it means:** A custom HTTP response header is disclosing a value that looks like a secret: a recognized credential token (AWS access key, Google API key, GitHub token, Slack token, JWT, Stripe secret key), a base64 key:iv pair like the nginx-ui X-Backup-Security backup-encryption leak, or a high-entropy string carried in a suspiciously named header (one containing key, secret, token, auth, signature, hmac, session, credential, and similar). Because secret scanning usually focuses on response bodies, secrets in headers are easy to overlook, yet they are returned to every client that receives the response.

**How it's exploited:** Anyone who can read the response, including a passive network observer, cached copy, or proxy log, harvests the leaked credential and replays it to authenticate as the application, decrypt protected data, or call the associated cloud or third-party API directly. The leaked material can grant the same access the application itself holds.

**Fix:** Remove secrets, keys, and tokens from response headers and rotate any value that has already been exposed.`

	ModuleConfirmation = "Confirmed when a non-standard response header carries a value matching known sensitive token formats or a high-entropy key-shaped string"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "secrets", "headers", "light"}
)
