package javascript_uri_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "javascript-uri-sink"
	ModuleName  = "JavaScript URI Sink Detection"
	ModuleShort = "Detects javascript: URIs reflected in href/src attributes"
)

var (
	ModuleDesc = `**What it means:** A javascript: protocol URI was found inside a URL-based HTML attribute (href, src, action, or formaction) - an XSS sink. If the URI is built from unvalidated user input, an attacker can run script via it. Reported Firm when a request parameter is reflected into the sink, Tentative otherwise.

**How it's exploited:** An attacker crafts a link or form whose URL attribute begins with javascript: (including encoded variants); when the victim clicks or submits, the script runs in their session.

**Fix:** Reject or strip javascript: and other non-http schemes, and allow-list only safe protocols like http/https/mailto.`

	ModuleConfirmation = "Confirmed when javascript: URI is found in a URL-based HTML attribute, especially when correlated with request input"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
