package client_prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-prototype-pollution"
	ModuleName  = "Client-Side Prototype Pollution"
	ModuleShort = "Detects client-side prototype pollution via JavaScript static analysis"
)

var (
	ModuleDesc = `**What it means:** The page's JavaScript parses URL parameters with a pattern vulnerable to client-side prototype pollution (jQuery deep extend, lodash merge/set/defaultsDeep, or a recursive location.search/hash parser), letting attacker keys like __proto__ write onto Object.prototype. Found via static analysis of inline and same-origin scripts.

**How it's exploited:** An attacker sends a crafted link like ?__proto__[polluted]=true; the polluted property flows into a gadget (innerHTML, eval, document.write), typically yielding DOM-based XSS or auth-logic bypass. Identified statically, so verify manually.

**Fix:** Avoid recursive merge of untrusted URL input, strip __proto__ and constructor keys, and use Object.create(null) or Map for parameter stores.`

	ModuleConfirmation = "Confirmed when JavaScript static analysis identifies known prototype pollution source patterns in the page's scripts"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "xss", "light"}
)
