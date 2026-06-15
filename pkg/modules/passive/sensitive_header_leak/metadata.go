package sensitive_header_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-header-leak"
	ModuleName  = "Sensitive Data in Response Headers"
	ModuleShort = "Detects high-entropy / key-shaped values disclosed in custom response headers"
)

var (
	ModuleDesc = `**What it means:** A custom HTTP response header discloses a value that looks like a secret: a recognized credential token (AWS, Google, GitHub, Slack, JWT, Stripe), a base64 key:iv pair, or a high-entropy string in a suspiciously named header. Secrets in headers are easy to overlook yet returned to every client.

**How it's exploited:** Anyone who reads the response, including a network observer, cache, or proxy log, harvests the credential and replays it to authenticate as the application or call its API.

**Fix:** Remove secrets, keys, and tokens from response headers and rotate any value already exposed.`

	ModuleConfirmation = "Confirmed when a non-standard response header carries a value matching known sensitive token formats or a high-entropy key-shaped string"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "secrets", "headers", "light"}
)
