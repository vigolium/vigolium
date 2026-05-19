package javascript_uri_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "javascript-uri-sink"
	ModuleName  = "JavaScript URI Sink Detection"
	ModuleShort = "Detects javascript: URIs reflected in href/src attributes"
)

var (
	ModuleDesc = `## Description
Detects javascript: protocol URIs in HTML attributes that act as XSS sinks.
When user-controlled data flows into href, src, or other URL-based attributes
without protocol validation, an attacker can inject javascript: URIs to achieve
script execution on user interaction (e.g., clicking a link).

This is a distinct vector from general DOM XSS — React's default data binding
does not protect against javascript: URIs in href attributes.

## Notes
- Scans HTML responses for javascript: URIs in href, src, action, formaction attributes
- Correlates with request parameters to identify reflection from user input
- Flags both direct javascript: URIs and obfuscated variants (url-encoded, mixed case)
- Deduplicates by host+path

## References
- https://owasp.org/www-community/attacks/xss/
- https://snyk.io/blog/10-react-security-best-practices/
- https://cwe.mitre.org/data/definitions/79.html`

	ModuleConfirmation = "Confirmed when javascript: URI is found in a URL-based HTML attribute, especially when correlated with request input"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
