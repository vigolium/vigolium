package sensitive_header_leak

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sensitive-header-leak"
	ModuleName  = "Sensitive Data in Response Headers"
	ModuleShort = "Detects high-entropy / key-shaped values disclosed in custom response headers"
)

var (
	ModuleDesc = `**What it means:** A non-cookie response header contains a recognized token format, a base64 key/IV pair, or a constrained high-entropy value under a credential-shaped header name. Public identifiers and redirect/authentication-flow artifacts remain observations; private formats are candidates.

**How it's exploited:** Anyone who reads the response, including a network observer, cache, or proxy log, harvests the credential and replays it to authenticate as the application or call its API.

**Fix:** Remove secrets, keys, and tokens from response headers and rotate any value already exposed.`

	ModuleConfirmation = "Candidate for private-token formats or constrained high-entropy custom headers; public identifiers, examples, redirects, challenges, and cookie values are not confirmed secret leaks"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "secrets", "headers", "light"}
)
