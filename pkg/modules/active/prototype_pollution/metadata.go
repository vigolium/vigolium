package prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "prototype-pollution"
	ModuleName  = "Prototype Pollution"
	ModuleShort = "Detects server-side prototype pollution via JSON injection"
)

var (
	ModuleDesc = `**What it means:** A server-side JavaScript application (typically Node.js/Express) merges attacker-controlled JSON into objects without protecting special keys, letting a request alter Object.prototype. This changes properties shared by every object, corrupting logic and, depending on gadgets, escalating to privilege bypass, denial of service, or code execution.

**How it's exploited:** An attacker sends a JSON body with __proto__ or constructor.prototype keys to a write endpoint. The scanner confirms by forcing a polluted status or surfacing a canary via the prototype.

**Fix:** Reject or strip __proto__ and constructor keys; never recursively merge untrusted input.`

	ModuleConfirmation = "Confirmed when __proto__ or constructor.prototype injection causes observable changes in response status, headers, or body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "injection", "javascript", "moderate"}
)
