package ssr_data_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-data-exposure"
	ModuleName  = "SSR Data Exposure"
	ModuleShort = "Detects sensitive data leaked in server-side rendered state blobs"
)

var (
	ModuleDesc = `## Description
Scans server-side rendered (SSR) state blobs embedded in HTML pages for sensitive data
exposure. Modern JS frameworks serialize application state into the HTML page for hydration,
which may inadvertently include API keys, tokens, admin flags, email addresses,
password hashes, or internal URLs.

## Notes
- Passive only — does not send any HTTP requests
- Extracts state from: __NEXT_DATA__, __NUXT__, __INITIAL_STATE__, __APOLLO_STATE__
- Scans extracted JSON for API keys, tokens, admin flags, emails, password hashes, internal IPs
- Minimum token length of 16 characters to reduce false positives
- Deduplicates by host+path

## References
- https://nextjs.org/docs/pages/building-your-application/data-fetching
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption`

	ModuleConfirmation = "Confirmed when sensitive patterns (API keys, tokens, admin flags, credentials) are found in SSR state blobs"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"javascript", "info-disclosure", "light"}
)
