package nextjs_data_leakage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-data-leakage"
	ModuleName  = "Next.js Data Route Leakage"
	ModuleShort = "Detects unauthorized access to Next.js data routes on auth-protected pages"
)

var (
	ModuleDesc = `## Description
Detects Next.js data route leakage where authenticated page data can be accessed
without authorization. Next.js Pages Router exposes JSON data at predictable
/_next/data/<buildId>/<path>.json URLs. When authentication middleware protects
the HTML page but not the data route, sensitive page props leak.

## Notes
- Only activates on 302/401/403 responses from Next.js hosts
- Requires buildId extraction (from shared cache or response body)
- Validates JSON response contains pageProps and is not a notFound page
- Deduplicates by host+path

## References
- https://nextjs.org/docs/pages/building-your-application/data-fetching
- https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps`

	ModuleConfirmation = "Confirmed when the data route returns 200 with valid pageProps JSON for an auth-protected page"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"nextjs", "javascript", "authentication", "info-disclosure", "light"}
)
