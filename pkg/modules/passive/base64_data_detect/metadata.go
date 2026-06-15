package base64_data_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "base64-data-detect"
	ModuleName  = "Base64 Data Detect"
	ModuleShort = "Identifies interesting base64 encoded data like JSON, PHP Object in requests/responses"
)

var (
	ModuleDesc = `**What it means:** Base64-encoded data was spotted whose decoded prefix matches a security-relevant format: JSON/JWT (eyJ), PHP serialized (YTo, Tzo), XML/PHP tags (PD8), or a Java serialized object (rO0). Base64 is not encryption, so the data is readable. Informational signal.

**How it's exploited:** The blob marks where the app moves structured state through a parameter, cookie, or body. An attacker decodes it to forge or replay JSON/JWT claims, or supplies a crafted serialized payload that may trigger insecure deserialization.

**Fix:** Treat client-supplied encoded values as untrusted: integrity-protect tokens, validate decoded structures, and avoid native deserialization of PHP or Java objects.`

	ModuleConfirmation = "Confirmed when request or response contains base64-encoded data matching known interesting prefixes (JSON, PHP objects, URLs, Java objects)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"info-disclosure", "deserialization", "light"}
)
