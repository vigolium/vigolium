package serialized_object_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "serialized-object-detect"
	ModuleName  = "Serialized Object Detection"
	ModuleShort = "Detects serialized Java/PHP/.NET/Python/Ruby/Node.js objects in request parameters (incl. base64-wrapped)"
)

var (
	ModuleDesc = `**What it means:** A request parameter (query, path, cookie, or body) carries a serialized object whose byte signature matches a known Java, PHP, .NET, Python, Ruby, or Node.js format, including base64-wrapped values. Accepting client-controllable serialized data drives insecure deserialization. This signature check confirms an attack surface, not exploitability.

**How it's exploited:** If the server deserializes the value without strict type allow-listing, an attacker supplies a crafted object that triggers gadget chains, leading to remote code execution, auth bypass, or object injection.

**Fix:** Avoid deserializing untrusted input; if unavoidable, use JSON with schema validation or strict class allow-listing.`

	ModuleConfirmation = "Confirmed when request parameter values contain known serialization format signatures"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "light"}
)
