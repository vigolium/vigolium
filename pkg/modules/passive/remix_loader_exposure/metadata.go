package remix_loader_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "remix-loader-exposure"
	ModuleName  = "Remix Loader Exposure"
	ModuleShort = "Detects sensitive data leaked through Remix loader data and context"
)

var (
	ModuleDesc = `## Description
Scans HTML responses for Remix framework-specific patterns that may leak sensitive data.
Detects exposed Remix context (window.__remixContext), manifest (__remixManifest), Remix
response headers, and loader data embedded in script tags. Extracts Remix state data and
scans for sensitive patterns including API keys, tokens, admin flags, email addresses,
password hashes, internal IPs, database URLs, and AWS keys.

## Notes
- Passive only - does not send any HTTP requests
- Detects: window.__remixContext, __remixManifest, X-Remix-Response/X-Remix-Revalidate headers
- Extracts loader data from script tags and scans for sensitive patterns
- Minimum token length of 16 characters to reduce false positives
- Deduplicates by host+path

## References
- https://remix.run/docs/en/main/route/loader
- https://remix.run/docs/en/main/guides/streaming
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption`

	ModuleConfirmation = "Confirmed when sensitive data patterns are found in Remix loader data or context"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"javascript", "info-disclosure", "light"}
)
