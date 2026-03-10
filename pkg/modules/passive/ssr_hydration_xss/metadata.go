package ssr_hydration_xss

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-hydration-xss"
	ModuleName  = "SSR Hydration XSS Detection"
	ModuleShort = "Detects potential XSS in server-side rendered JSON hydration scripts"
)

var (
	ModuleDesc = `## Description
Detects unsafe patterns in server-side rendered (SSR) pages where JSON data is
embedded in inline script tags for client-side hydration. If the serialized JSON
is not properly encoded, an attacker can inject a closing </script> tag followed
by arbitrary HTML/JavaScript, leading to XSS on page load.

Common vulnerable patterns include:
- __NEXT_DATA__ script tags with unescaped user content
- window.__PRELOADED_STATE__ assignments with raw JSON.stringify output
- Hydration scripts that embed user-controlled data without HTML escaping

## Notes
- Scans HTML responses for inline script tags containing hydration data
- Detects unescaped </script> sequences within JSON hydration blocks
- Checks for missing HTML entity encoding of < characters in embedded JSON
- Correlates with request parameters to identify user-controlled data in hydration
- Deduplicates by host+path

## References
- https://snyk.io/blog/10-react-security-best-practices/
- https://owasp.org/www-community/attacks/xss/
- https://cwe.mitre.org/data/definitions/79.html`

	ModuleConfirmation = "Confirmed when user-controlled data appears unescaped in a JSON hydration script block"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags = []string{"xss", "javascript", "light"}
)
