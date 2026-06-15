package file_upload_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "file-upload-scan"
	ModuleName  = "File Upload Scanner"
	ModuleShort = "Tests for arbitrary file upload and execution vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The file upload endpoint accepts a dangerous file (PHP script, .htaccess, SVG, or HTML) and stores it where it can be retrieved over the web. This unrestricted upload flaw is severe, since the attacker controls the content and URL.

**How it's exploited:** An attacker uploads via a server-side extension or bypass (double extension, null byte, .phtml, .phar), then fetches it back served verbatim, yielding remote code execution, stored XSS, or XXE/SSRF.

**Fix:** Allowlist safe extensions and content types, store uploads outside the web root or on non-executing storage, and randomize filenames.`

	ModuleConfirmation = "Confirmed when an uploaded file is accessible and contains the unique scan marker, indicating arbitrary file upload and potential code execution"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
