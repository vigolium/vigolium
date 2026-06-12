package pdf_generation_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "pdf-generation-injection"
	ModuleName  = "PDF Generation Injection"
	ModuleShort = "Detects HTML/JS injection into server-side PDF generation endpoints for SSRF/file read"
)

var (
	ModuleDesc = `**What it means:** A server-side PDF generation endpoint (for example wkhtmltopdf, Puppeteer, WeasyPrint, or Prince converting HTML to PDF) renders attacker-supplied input as live HTML/JavaScript instead of treating it as plain text. This module confirmed injected markup was processed by the renderer, seen as marker reflection inside a PDF response or an out-of-band callback from injected resource tags.

**How it's exploited:** An attacker submits HTML tags such as an img, link, iframe, or script that load remote or local URLs into a content parameter. The headless renderer fetches them from inside the server's network, enabling SSRF against internal services and cloud metadata endpoints, reading local files via the file scheme, and JavaScript execution in the rendering context, which can leak sensitive data into the generated document.

**Fix:** Treat user input as untrusted text by sanitizing or escaping it before rendering, and run the PDF generator with remote resource loading, the file scheme, and outbound network access disabled.`
	ModuleConfirmation = "Confirmed when injected HTML/JS payloads produce evidence of server-side rendering in the response (PDF markers, reflected injection artifacts, or OAST callbacks)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "moderate"}
)
