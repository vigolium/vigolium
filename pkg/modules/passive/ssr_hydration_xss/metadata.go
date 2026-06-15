package ssr_hydration_xss

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-hydration-xss"
	ModuleName  = "SSR Hydration XSS Detection"
	ModuleShort = "Detects potential XSS in server-side rendered JSON hydration scripts"
)

var (
	ModuleDesc = `**What it means:** A server-rendered page embeds JSON hydration state in an inline script block (Next.js __NEXT_DATA__, __APOLLO_STATE__, or Remix __remixContext) without safe encoding. The scanner flags an unescaped </script> in the block (High) or a raw < in a JSON string (Medium). A likely XSS flaw on page load.

**How it's exploited:** An attacker supplies input reaching the serialized state with a closing </script> tag that ends the script early, injecting JavaScript that runs in the victim's session.

**Fix:** Serialize hydration data with an HTML-safe encoder that escapes < so user content cannot break out of the script.`

	ModuleConfirmation = "Confirmed when user-controlled data appears unescaped in a JSON hydration script block"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
