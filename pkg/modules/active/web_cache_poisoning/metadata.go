package web_cache_poisoning

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "web-cache-poisoning"
	ModuleName  = "Web Cache Poisoning"
	ModuleShort = "Detects web cache poisoning via unkeyed header injection"
)

var (
	ModuleDesc = `## Description
Detects web cache poisoning vulnerabilities by injecting values via unkeyed headers
(X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL) and checking for reflection.

## Notes
- Tests unkeyed headers that may influence cached responses
- Checks for header value reflection in response body
- Analyzes cache-related headers (Age, X-Cache, Cache-Control)
- Runs per-request to test endpoint-specific caching behavior

## References
- https://portswigger.net/web-security/web-cache-poisoning
- https://portswigger.net/research/practical-web-cache-poisoning`

	ModuleConfirmation = "Confirmed when unkeyed header values are reflected in the response body, indicating cache-poisoning potential"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"cache-poisoning", "header-security", "moderate"}
)
