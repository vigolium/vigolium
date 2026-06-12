package content_type_mismatch

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "content-type-mismatch"
	ModuleName  = "Content Type Mismatch"
	ModuleShort = "Detects mismatches between Content-Type header and response body"
)

var (
	ModuleDesc = `**What it means:** The response declares one Content-Type but its body is actually a different format (for example, a JSON or XML payload served as text/html, or an HTML page served as application/json). This mismatch confuses browsers about how to handle the response and is a sign of MIME-type misconfiguration. The finding also reports whether the X-Content-Type-Options: nosniff header is present.
**How it's exploited:** When the declared type is wrong and nosniff is missing, a browser may MIME-sniff the body and interpret it as a more dangerous type than intended (for example treating user-controlled content as HTML/script), which can turn a reflected payload into stored or reflected cross-site scripting. Even without sniffing, mislabeled responses can break content-handling assumptions in downstream consumers.
**Fix:** Set an accurate Content-Type that matches the actual body and always send X-Content-Type-Options: nosniff on responses that carry untrusted or non-HTML content.`

	ModuleConfirmation = "Confirmed when the Content-Type header does not match the actual content of the response body"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "light"}
)
