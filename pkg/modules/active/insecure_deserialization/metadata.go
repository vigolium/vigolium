package insecure_deserialization

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "insecure-deserialization"
	ModuleName  = "Insecure Deserialization"
	ModuleShort = "Detects insecure deserialization via error-based detection"
)

var (
	ModuleDesc = `**What it means:** A request parameter feeds attacker-controlled data into an unsafe deserialization routine. The scanner injected serialized object payloads for Java, PHP, Python, Ruby, and .NET into a body parameter and the application returned a framework-specific deserialization error (for example a Java ObjectInputStream/InvalidClassException stack trace, a PHP unserialize() fatal error, a Python pickle/YAML error, a Ruby Marshal.load error, or a .NET BinaryFormatter/TypeNameHandling message) that was not present in the original baseline response. This proves the endpoint deserializes untrusted input, a high-impact flaw.

**How it's exploited:** An attacker crafts a malicious serialized object using gadget chains (such as ysoserial for Java or known PHP/.NET/Ruby gadgets) so that the deserialization process instantiates dangerous objects, frequently leading to remote code execution on the server, and otherwise to denial of service, authentication bypass, or arbitrary file access.

**Fix:** Never deserialize untrusted input; use safe data formats such as JSON with strict schemas, and if deserialization is unavoidable enforce type allow-lists and integrity checks on the payload.`

	ModuleConfirmation = "Confirmed when injected serialized payloads trigger deserialization error messages in the response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"deserialization", "rce", "moderate"}
)
