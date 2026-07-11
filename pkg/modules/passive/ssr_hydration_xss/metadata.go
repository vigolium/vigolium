package ssr_hydration_xss

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "ssr-hydration-xss"
	ModuleName  = "SSR Hydration XSS Detection"
	ModuleShort = "Detects potential XSS in server-side rendered JSON hydration scripts"
)

var (
	ModuleDesc = `**What it means:** Recognized hydration data is structurally truncated at a script end-tag while still inside a value, followed by executable markup. Raw less-than characters inside JSON are ignored. Passive evidence remains a candidate pending controlled browser replay.

**How it's exploited:** Attacker input forms a closing script tag, escapes serialized state, and injects JavaScript into the victim's page.

**Fix:** Use an HTML-safe serializer that escapes less-than characters, preventing user content from forming a script end-tag.`

	ModuleConfirmation = "Candidate when a hydration serialization is structurally truncated at a script boundary and executable markup follows; confirmed only by controlled reflection and browser execution"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"xss", "javascript", "light"}
)
