package cache_deception

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-deception"
	ModuleName  = "Web Cache Deception"
	ModuleShort = "Detects web cache deception via path confusion with static file extensions"
)

var (
	ModuleDesc = `**What it means:** This URL is vulnerable to web cache deception. By appending a static-looking suffix to the path (a fake extension like .css/.js/.png/.svg, or an encoded path-separator trick such as %2f.css or /..%2f..%2fstatic.css), the request still returns the original authenticated 2xx content, but the reverse proxy or CDN treats it as a cacheable static asset and stores that private response. The scanner confirmed this by re-requesting the crafted path and observing a cache HIT (X-Cache, CF-Cache-Status, X-Cache-Status, or a non-zero Age) while the body still matched the authenticated baseline.

**How it's exploited:** An attacker lures a logged-in victim into loading the crafted URL; the victim's own authenticated page (session data, personal or account information) gets written into the shared cache, and the attacker then fetches the same cached URL with no credentials to read the victim's private content.

**Fix:** Configure the cache and origin to key on the real content type and never cache responses to authenticated, non-static paths, and reject or normalize path-confusion suffixes before caching.`
	ModuleConfirmation = "Confirmed when a path-confused request returns the same successful (2xx) authenticated content as the original and cache indicators (Age, X-Cache, CF-Cache-Status) suggest the response was cached. Cached CDN error pages (e.g. a 5xx with 'X-Cache: Error') are not deception and are excluded."
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "auth-bypass", "moderate"}
)
