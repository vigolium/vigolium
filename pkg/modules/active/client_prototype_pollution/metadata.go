package client_prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "client-prototype-pollution"
	ModuleName  = "Client-Side Prototype Pollution"
	ModuleShort = "Detects client-side prototype pollution via JavaScript static analysis"
)

var (
	ModuleDesc = `**What it means:** Inline or same-origin JavaScript contains a nearby URL-source and recursive merge/property-write pattern associated with client-side prototype pollution. Generic params and cross-origin scripts are excluded.

**How it's exploited:** A real exploit requires the crafted key to reach the write, alter Object.prototype at runtime, and flow into a useful gadget. Gadgets found elsewhere in the page are enrichment, not connected-flow proof.

**Fix:** Avoid recursive merge of untrusted URL input, strip __proto__ and constructor keys, and use Object.create(null) or Map for parameter stores.`

	ModuleConfirmation = "Candidate after same-origin source-pattern proximity and optional reachability probe; runtime prototype mutation and source-to-gadget flow remain unconfirmed"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"prototype-pollution", "xss", "light"}
)
