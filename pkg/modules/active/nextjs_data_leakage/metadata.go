package nextjs_data_leakage

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "nextjs-data-leakage"
	ModuleName  = "Next.js Data Route Leakage"
	ModuleShort = "Detects unauthorized access to Next.js data routes on auth-protected pages"
)

var (
	ModuleDesc = `**What it means:** An authentication-protected Next.js (Pages Router) page returns the same data to an unauthenticated request through its underlying JSON data route. The HTML page is gated by 401/403 or a login redirect, but the predictable /_next/data/<buildId>/<path>.json endpoint serves the page's protected props with no credentials, exposing data that should require a valid session.

**How it's exploited:** An attacker that hits the protected page gets denied, but rederives the buildId and requests the matching /_next/data/ JSON route with the session cookie and Authorization header stripped. Because authorization is enforced only on the HTML route, the data route returns 200 with the full pageProps payload, leaking the sensitive account, user, or business data the page was meant to protect, with no login required.

**Fix:** Apply the same authentication and authorization checks to the /_next/data/ data routes as to the rendered pages (enforce auth in getServerSideProps or middleware that also covers the data path), so unauthenticated data requests are denied.`

	ModuleConfirmation = "Confirmed when the data route returns 200 with valid pageProps JSON for an auth-protected page"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"nextjs", "javascript", "authentication", "info-disclosure", "light"}
)
