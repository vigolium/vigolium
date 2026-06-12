package secret_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "secret-detect"
	ModuleName  = "Secret Detection"
	ModuleShort = "Detects leaked secrets and credentials in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** A secret was found exposed in an HTTP response body, such as an API key, access token, password, private key, or database connection string. This module passively scans text-based responses with the Kingfisher detection engine, so the secret is being served to anyone who can reach the page or asset. Secrets that Kingfisher actively validates as live are escalated to Critical severity.

**How it's exploited:** An attacker who reads the response harvests the credential and reuses it directly against the corresponding service (cloud account, third-party API, database, signing key), gaining whatever access the secret grants without needing to compromise anything else. Leaked keys are routinely scraped from public pages, JavaScript bundles, and config endpoints and abused for account takeover, data theft, or cloud resource abuse.

**Fix:** Remove the secret from the response, rotate the exposed credential immediately, and keep secrets in server-side configuration or a secrets manager rather than anything sent to clients.`

	ModuleConfirmation = "Confirmed when Kingfisher detects a known secret pattern in the HTTP response body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"info-disclosure", "file-exposure", "light"}
)
