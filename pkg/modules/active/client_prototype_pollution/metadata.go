package client_prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-prototype-pollution"
	ModuleName  = "Client-Side Prototype Pollution"
	ModuleShort = "Detects client-side prototype pollution via JavaScript static analysis"
)

var (
	ModuleDesc = `**What it means:** The page's JavaScript parses URL parameters into objects using a pattern known to be vulnerable to client-side prototype pollution (for example jQuery deep extend, lodash merge/set/defaultsDeep, or a custom recursive parser of location.search/hash). This lets attacker-controlled keys such as __proto__ or constructor.prototype write onto Object.prototype, contaminating every object in the browser. The finding is corroborated by static analysis of the inline and same-origin external scripts (CDN libraries are skipped), and where present, reports exploitable gadgets (innerHTML, eval, script.src, document.write, jQuery .html()).

**How it's exploited:** An attacker sends a victim a crafted link like https://target/page?__proto__[polluted]=true; when the victim opens it the polluted prototype property flows into a gadget, typically yielding DOM-based XSS, or otherwise authentication-logic bypass or denial of service depending on the gadget. Confidence is Firm: the polluting code path is identified statically rather than triggered, so manual confirmation is recommended.

**Fix:** Avoid recursive merge of untrusted URL input, reject or strip __proto__ and constructor keys, and use Object.create(null) or Map for parameter stores.`

	ModuleConfirmation = "Confirmed when JavaScript static analysis identifies known prototype pollution source patterns in the page's scripts"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "xss", "light"}
)
