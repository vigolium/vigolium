package cacheable_https_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cacheable-https-detect"
	ModuleName  = "Cacheable HTTPS Response Detect"
	ModuleShort = "Detects sensitive HTTPS responses without proper cache control"
)

var (
	ModuleDesc = `## Description
Passively detects HTTPS responses containing sensitive content (Set-Cookie headers or
password fields) that lack proper cache-control directives, allowing browsers or proxies
to cache sensitive data.

## Notes
- Only fires on HTTPS URLs with sensitive response indicators
- Checks for Cache-Control: no-store, no-cache, or private
- Also checks Pragma: no-cache as legacy fallback
- Missing or permissive cache control on sensitive responses is flagged

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control`

	ModuleConfirmation = "Confirmed when sensitive HTTPS response lacks Cache-Control: no-store/no-cache/private directives"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"misconfiguration", "header-security", "light"}
)
