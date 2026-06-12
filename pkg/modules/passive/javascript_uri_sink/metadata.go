package javascript_uri_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "javascript-uri-sink"
	ModuleName  = "JavaScript URI Sink Detection"
	ModuleShort = "Detects javascript: URIs reflected in href/src attributes"
)

var (
	ModuleDesc = `**What it means:** This passive check found a javascript: protocol URI sitting inside a URL-based HTML attribute (href, src, action, or formaction) in the page returned by the server. Such an attribute is an XSS sink: if the URI is built from user-controlled input that is not protocol-validated, an attacker can supply a javascript: URI that runs script in the victim's browser. The finding is reported as Firm when a request parameter value is seen reflected inside the matched sink, and Tentative otherwise.

**How it's exploited:** An attacker crafts a link or form whose URL attribute begins with javascript: (including url-encoded or HTML-entity-obfuscated variants to dodge naive filters). When the victim clicks the link or submits the form, the script runs in their session, enabling cookie theft, account actions, or defacement. Reflected parameters make this attacker-controllable via a malicious URL.

**Fix:** Reject or strip javascript: (and other non-http) schemes when building URL attributes, allow-list only safe protocols such as http/https/mailto, and never place untrusted input into href/src without scheme validation.`

	ModuleConfirmation = "Confirmed when javascript: URI is found in a URL-based HTML attribute, especially when correlated with request input"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
