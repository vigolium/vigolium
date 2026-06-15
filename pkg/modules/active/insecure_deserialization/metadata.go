package insecure_deserialization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "insecure-deserialization"
	ModuleName  = "Insecure Deserialization"
	ModuleShort = "Detects insecure deserialization via error-based detection"
)

var (
	ModuleDesc = `**What it means:** A request parameter feeds attacker-controlled data into an unsafe deserialization routine. Injected serialized payloads (Java, PHP, Python, Ruby, .NET) triggered a framework-specific deserialization error absent from the baseline, proving the endpoint deserializes untrusted input.

**How it's exploited:** An attacker crafts a malicious object using gadget chains (such as ysoserial) so deserialization instantiates dangerous objects, frequently leading to remote code execution, or otherwise denial of service, authentication bypass, or arbitrary file access.

**Fix:** Never deserialize untrusted input; use safe formats like JSON with strict schemas, and if unavoidable enforce type allow-lists and payload integrity checks.`

	ModuleConfirmation = "Confirmed when injected serialized payloads trigger deserialization error messages in the response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "rce", "moderate"}
)
