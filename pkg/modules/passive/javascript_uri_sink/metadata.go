package javascript_uri_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "javascript-uri-sink"
	ModuleName  = "JavaScript URI Sink Detection"
	ModuleShort = "Detects javascript: URIs reflected in href/src attributes"
)

var (
	ModuleDesc = `**What it means:** A javascript: URI was found in a URL-based HTML attribute (href, src, action, formaction) - a potential XSS sink, exploitable only when built from unvalidated input. Reported Medium/Firm when a request parameter is reflected into the URI; a static URI is Info/Tentative, and browser no-ops (javascript:void(0)) and framework postback helpers (__doPostBack, form.submit()) are not reported.

**How it's exploited:** An attacker crafts a link or form whose URL attribute begins with javascript: (including encoded variants) from reflected input; clicking or submitting runs the script in the victim's session.

**Fix:** Reject non-http schemes and allow-list safe protocols (http/https/mailto).`

	ModuleConfirmation = "Confirmed when a request parameter value is reflected into a javascript: URI in a URL-based HTML attribute (Medium/Firm); a static javascript: URI with no reflected input is an Info observation"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
