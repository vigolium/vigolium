package unsafe_html_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "unsafe-html-sink"
	ModuleName  = "Unsafe HTML Sink"
	ModuleShort = "Detects raw HTML injection sinks in JS/TS framework code"
)

var (
	ModuleDesc = `## Description
Scans JavaScript, TypeScript, Vue, and Svelte response bodies for patterns that inject
raw HTML into the DOM without sanitization. These sinks are common sources of XSS
vulnerabilities in modern frontend frameworks: React (dangerouslySetInnerHTML),
Vue (v-html), Svelte ({@html}), Angular (bypassSecurityTrust*), and vanilla DOM APIs
(innerHTML, outerHTML, insertAdjacentHTML, document.write). Also detects dangerous
code injection patterns via eval() and new Function().

## Notes
- Passive only -- does not send any HTTP requests
- Scans JS/TS/Vue/Svelte files and inline scripts in HTML responses
- Each detected pattern produces a separate finding
- Deduplicates by host+path
- eval() detections are suppressed for test/spec/mock files

## References
- https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
- https://vuejs.org/api/built-in-directives.html#v-html
- https://svelte.dev/docs/special-tags#html
- https://angular.io/api/platform-browser/DomSanitizer
- https://owasp.org/www-community/attacks/DOM_Based_XSS
- https://cwe.mitre.org/data/definitions/79.html`

	ModuleConfirmation = "Confirmed when response JavaScript or template code contains known unsafe HTML injection sinks"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "javascript", "light"}
)
