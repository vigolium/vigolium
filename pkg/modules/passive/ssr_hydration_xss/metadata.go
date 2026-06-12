package ssr_hydration_xss

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-hydration-xss"
	ModuleName  = "SSR Hydration XSS Detection"
	ModuleShort = "Detects potential XSS in server-side rendered JSON hydration scripts"
)

var (
	ModuleDesc = `**What it means:** A server-side rendered HTML page embeds JSON hydration state in an inline script block (Next.js __NEXT_DATA__/__next_f.push, window.__PRELOADED_STATE__/__INITIAL_STATE__/__APOLLO_STATE__/__NUXT__, or Remix __remixContext) without safely encoding the data. The scanner flags two cases: an unescaped </script> sequence inside the block (script-context breakout, reported High), or a raw < inside a JSON string value not encoded as \u003c or &lt; (reported Medium, raised to Firm when the value matches a request query parameter). This is a likely cross-site scripting (XSS) flaw that runs as soon as the page loads.

**How it's exploited:** An attacker supplies input that reaches the serialized state and includes a closing </script> tag (or a raw <) which prematurely ends the script element, letting them inject arbitrary HTML and JavaScript that executes in the victim's session to steal cookies, hijack accounts, or perform actions as the user.

**Fix:** Serialize hydration data with an HTML-safe encoder that escapes < as \u003c (and &lt;) so user-controlled content can never break out of the script context.`

	ModuleConfirmation = "Confirmed when user-controlled data appears unescaped in a JSON hydration script block"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
