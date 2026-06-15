package content_type_mismatch

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "content-type-mismatch"
	ModuleName  = "Content Type Mismatch"
	ModuleShort = "Detects mismatches between Content-Type header and response body"
)

var (
	ModuleDesc = `**What it means:** The response declares one Content-Type but the body is a different format (JSON/XML served as text/html, or HTML served as application/json). This MIME misconfiguration confuses browsers; the finding reports whether X-Content-Type-Options: nosniff is present.

**How it's exploited:** When the type is wrong and nosniff is missing, a browser may MIME-sniff the body as a more dangerous type (user-controlled content as HTML/script), turning a reflected payload into cross-site scripting. Mislabeled responses also break downstream content handling.

**Fix:** Set an accurate Content-Type matching the body and always send X-Content-Type-Options: nosniff on responses carrying untrusted or non-HTML content.`

	ModuleConfirmation = "Confirmed when the Content-Type header does not match the actual content of the response body"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"misconfiguration", "header-security", "light"}
)
