package cache_deception

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-deception"
	ModuleName  = "Web Cache Deception"
	ModuleShort = "Detects web cache deception via path confusion with static file extensions"
)

var (
	ModuleDesc = `**What it means:** This URL is vulnerable to web cache deception. Appending a static-looking suffix (a fake .css/.js extension or encoded path-separator like %2f.css) still returns authenticated 2xx content, but the proxy or CDN caches it as a static asset. Confirmed by a cache HIT matching the authenticated baseline.

**How it's exploited:** An attacker lures a logged-in victim into loading the crafted URL; the victim's authenticated page is cached, then the attacker fetches that cached URL with no credentials.

**Fix:** Configure the cache and origin to key on real content type and never cache authenticated non-static paths.`
	ModuleConfirmation = "Confirmed when a path-confused request returns the same successful (2xx) authenticated content as the original and cache indicators (Age, X-Cache, CF-Cache-Status) suggest the response was cached. Cached CDN error pages (e.g. a 5xx with 'X-Cache: Error') are not deception and are excluded."
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "auth-bypass", "moderate"}
)
