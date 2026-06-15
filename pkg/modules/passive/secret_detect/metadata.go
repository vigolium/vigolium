package secret_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "secret-detect"
	ModuleName  = "Secret Detection"
	ModuleShort = "Detects leaked secrets and credentials in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A secret (API key, access token, password, private key, or DB connection string) was found in an HTTP response, so it is served to anyone who can reach it. Live-validated secrets escalate to Critical; a match only on a redirect, header, or pre-auth JWT is downgraded.

**How it's exploited:** An attacker who reads the response harvests the credential and reuses it against the matching service for account takeover or data theft.

**Fix:** Remove and immediately rotate the secret, and keep secrets server-side or in a secrets manager, never in client-facing content.`

	ModuleConfirmation = "Confirmed when Kingfisher detects a known secret pattern in the HTTP response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
