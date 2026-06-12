package serialized_object_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "serialized-object-detect"
	ModuleName  = "Serialized Object Detection"
	ModuleShort = "Detects serialized Java/PHP/.NET/Python/Ruby/Node.js objects in request parameters (incl. base64-wrapped)"
)

var (
	ModuleDesc = `**What it means:** A request parameter (query, path, cookie, or body) carries a serialized object whose byte signature matches a known format for Java, PHP, .NET, Python, Ruby, or Node.js, including base64-wrapped values. The application accepts attacker-controllable serialized data from the client, which is exactly the input that drives insecure deserialization. This is a passive, signature-based detection: it confirms the presence of serialized input as a deserialization attack surface, not that the endpoint is provably exploitable.

**How it's exploited:** If the server deserializes this value without strict type allow-listing, an attacker can supply a crafted object that triggers dangerous gadget chains during deserialization, leading to remote code execution, authentication bypass, or object injection. Client-controlled serialized blobs in cookies or parameters are a classic vector (for example node-serialize _$$ND_FUNC$$_ payloads or Java/PHP/.NET/Python/Ruby gadgets).

**Fix:** Avoid deserializing untrusted input; if unavoidable, use a safe data format such as JSON with schema validation, or enforce strict type/class allow-listing and integrity checks (signed, tamper-proof state) on any serialized data accepted from clients.`

	ModuleConfirmation = "Confirmed when request parameter values contain known serialization format signatures"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "light"}
)
