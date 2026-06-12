package base64_data_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "base64-data-detect"
	ModuleName  = "Base64 Data Detect"
	ModuleShort = "Identifies interesting base64 encoded data like JSON, PHP Object in requests/responses"
)

var (
	ModuleDesc = `**What it means:** The scanner passively spotted base64-encoded data in an HTTP request or response whose decoded prefix matches a structured, security-relevant format: JSON or JWT (eyJ), PHP serialized arrays/objects (YTo, Tzo), XML or PHP source tags (PD8, PD9), embedded HTTP/HTTPS URLs (aHR0cHM6L, aHR0cDo), or a Java serialized object (rO0). This is an informational, manual-review signal, not a confirmed vulnerability. Base64 is not encryption, so the data is fully readable and may carry trust-bearing values or attacker-influenced input.

**How it's exploited:** The blob marks where the application moves structured state through a parameter, cookie, or body. An attacker decodes it and identifies where to tamper: forging or replaying JSON/JWT claims, or supplying a crafted PHP/Java serialized payload that could trigger insecure-deserialization code paths and, in the worst case, remote code execution. Embedded URLs may hint at SSRF or open-redirect surface.

**Fix:** Treat all client-supplied encoded values as untrusted input: integrity-protect tokens, validate decoded structures, and avoid native deserialization of PHP or Java objects from user data.`

	ModuleConfirmation = "Confirmed when request or response contains base64-encoded data matching known interesting prefixes (JSON, PHP objects, URLs, Java objects)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"info-disclosure", "deserialization", "light"}
)
