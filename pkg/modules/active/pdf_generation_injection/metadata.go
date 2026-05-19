package pdf_generation_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "pdf-generation-injection"
	ModuleName  = "PDF Generation Injection"
	ModuleShort = "Detects HTML/JS injection into server-side PDF generation endpoints for SSRF/file read"
)

var (
	ModuleDesc = `## Description
Detects injection vulnerabilities in server-side PDF generation endpoints. Applications using tools like
wkhtmltopdf, Puppeteer, WeasyPrint, or Prince to convert HTML to PDF may be vulnerable to HTML/JavaScript
injection. Attackers can inject markup that triggers SSRF (via external resource loading), local file
reads (via file:// protocol), or information disclosure.`
	ModuleConfirmation = "Confirmed when injected HTML/JS payloads produce evidence of server-side rendering in the response (PDF markers, reflected injection artifacts, or OAST callbacks)"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"ssrf", "injection", "moderate"}
)
