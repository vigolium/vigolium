package pdf_generation_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "pdf-generation-injection"
	ModuleName  = "PDF Generation Injection"
	ModuleShort = "Detects HTML/JS injection into server-side PDF generation endpoints for SSRF/file read"
)

var (
	ModuleDesc = `**What it means:** A PDF renderer processed attacker input as live HTML or JavaScript. Confirmation requires a runtime-only marker, recognizable local-file content, or an out-of-band callback; a PDF response or rendered payload text is insufficient.

**How it's exploited:** Injected tags make the server-side renderer fetch internal, remote, or file URLs, enabling SSRF or local-file reads.

**Fix:** Escape untrusted content and disable file access, remote resource loading, JavaScript, and outbound network access in the renderer.`
	ModuleConfirmation = "Confirmed only by runtime-generated PDF markers, recognizable local-file contents, or OAST callbacks; plain PDF responses and raw payload reflection are ignored"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "moderate"}
)
