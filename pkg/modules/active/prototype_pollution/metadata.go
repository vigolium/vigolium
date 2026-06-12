package prototype_pollution

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "prototype-pollution"
	ModuleName  = "Prototype Pollution"
	ModuleShort = "Detects server-side prototype pollution via JSON injection"
)

var (
	ModuleDesc = `**What it means:** The server-side JavaScript application (typically Node.js/Express) merges attacker-controlled JSON into objects without protecting special keys, letting a request alter Object.prototype. This server-side prototype pollution lets an attacker change properties shared by every object in the running process, which can corrupt application logic and, depending on the code paths and gadgets present, escalate to privilege bypass, denial of service, or remote code execution.

**How it's exploited:** An attacker sends a JSON body containing __proto__ or constructor.prototype keys (for example __proto__ with status set to 510, or an injected marker property) to a POST/PUT/PATCH endpoint. The scanner confirms pollution by reproducibly forcing a polluted HTTP status code or by surfacing a fresh canary value through the prototype while a normal echoed property does not reflect, proving the input reaches Object.prototype rather than being merely echoed back.

**Fix:** Avoid recursive merge of untrusted input into existing objects, reject or strip __proto__, constructor, and prototype keys, parse with a null-prototype/reviver, and freeze Object.prototype where feasible.`

	ModuleConfirmation = "Confirmed when __proto__ or constructor.prototype injection causes observable changes in response status, headers, or body"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"prototype-pollution", "injection", "javascript", "moderate"}
)
