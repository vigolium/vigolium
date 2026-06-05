package cache_deception

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cache-deception"
	ModuleName  = "Web Cache Deception"
	ModuleShort = "Detects web cache deception via path confusion with static file extensions"
)

var (
	ModuleDesc = `## Description
Detects Web Cache Deception vulnerabilities where appending static file extensions (e.g., .css, .js, .png)
to authenticated URLs causes reverse proxies or CDNs to cache sensitive responses. An attacker can trick
a victim into visiting a crafted URL, causing their authenticated response to be cached and subsequently
accessible to the attacker.`
	ModuleConfirmation = "Confirmed when a path-confused request returns the same successful (2xx) authenticated content as the original and cache indicators (Age, X-Cache, CF-Cache-Status) suggest the response was cached. Cached CDN error pages (e.g. a 5xx with 'X-Cache: Error') are not deception and are excluded."
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"cache-poisoning", "auth-bypass", "moderate"}
)
