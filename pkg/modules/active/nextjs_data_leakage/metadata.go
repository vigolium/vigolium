package nextjs_data_leakage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-data-leakage"
	ModuleName  = "Next.js Data Route Leakage"
	ModuleShort = "Detects unauthorized access to Next.js data routes on auth-protected pages"
)

var (
	ModuleDesc = `**What it means:** An auth-protected Next.js (Pages Router) page leaks its data to unauthenticated requests through its JSON data route. The HTML is gated by 401/403 or a login redirect, but the predictable /_next/data/<buildId>/<path>.json endpoint serves the props with no credentials.

**How it's exploited:** An attacker denied at the page rederives the buildId and requests the matching /_next/data/ route with cookie and Authorization stripped. Since authorization covers only the HTML route, the data route returns the full pageProps.

**Fix:** Apply the same auth checks to /_next/data/ routes as to rendered pages - enforce in getServerSideProps or covering middleware.`

	ModuleConfirmation = "Confirmed when the data route returns 200 with valid pageProps JSON for an auth-protected page"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "info-disclosure", "light"}
)
