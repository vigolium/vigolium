package dom_clobbering

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "dom-clobbering"
	ModuleName  = "DOM Clobbering Gadget"
	ModuleShort = "Flags JS that feeds a named-property global into a dangerous sink"
)

var (
	ModuleDesc = `**What it means:** Client JavaScript reads a value from a named-property global (window.X / document.X) and feeds it into a dangerous sink (script.src, location, innerHTML). Such globals can be overridden by an injected HTML element whose id/name matches — DOM clobbering.

**How it's exploited:** Where an HTML-injection point exists, an attacker injects markup like <a id=X href=//evil> so the JS global resolves to an attacker-controlled HTMLElement, redirecting a script load, navigation, or markup sink — without any script.

**Fix:** Do not read configuration from named globals; use explicit trusted references with type checks, and sanitize HTML with a clobbering-aware sanitizer.`

	ModuleConfirmation = "Reported when JS assigns a sink (script.src/href/innerHTML/location) from a non-standard named-property global (window.X / document.X)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"client-side", "dom-clobbering", "javascript", "light"}
)
