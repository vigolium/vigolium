package pdf_generation_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "pdf-generation-injection"
	ModuleName  = "PDF Generation Injection"
	ModuleShort = "Detects HTML/JS injection into server-side PDF generation endpoints for SSRF/file read"
)

var (
	ModuleDesc = `**What it means:** A server-side PDF endpoint (wkhtmltopdf, Puppeteer, WeasyPrint, Prince) renders attacker-supplied input as live HTML/JavaScript instead of plain text, confirmed by marker reflection or an out-of-band callback.

**How it's exploited:** An attacker submits img, link, iframe, or script tags loading remote or local URLs into a content parameter. The headless renderer fetches them from inside the server's network, enabling SSRF against internal services and metadata, file-scheme reads, and data-leaking JavaScript execution.

**Fix:** Sanitize or escape user input before rendering, and run the generator with remote resource loading and outbound network access disabled.`
	ModuleConfirmation = "Confirmed when injected HTML/JS payloads produce evidence of server-side rendering in the response (PDF markers, reflected injection artifacts, or OAST callbacks)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "moderate"}
)
