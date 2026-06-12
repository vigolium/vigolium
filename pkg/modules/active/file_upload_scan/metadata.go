package file_upload_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "file-upload-scan"
	ModuleName  = "File Upload Scanner"
	ModuleShort = "Tests for arbitrary file upload and execution vulnerabilities"
)

var (
	ModuleDesc = `**What it means:** The file upload endpoint accepts a dangerous file (such as a PHP script, .htaccess, SVG, or HTML page) and stores it where it can later be retrieved over the web. This is an unrestricted file upload flaw, one of the most damaging web vulnerabilities, because the attacker controls both the file content and its eventual URL.

**How it's exploited:** An attacker uploads a malicious file using a server-side extension or a bypass trick (double extension, null byte, case variation, JPEG magic-byte prefix, .htaccess, .phtml, .phar, or a traversal filename), then fetches it back from the disclosed path or a common uploads directory and confirms it is served verbatim. Depending on file type this yields remote code execution (PHP/PHAR/.htaccess), stored XSS (HTML), or XXE/SSRF and local file read (SVG), giving full server or account compromise.

**Fix:** Validate uploads against an allowlist of safe extensions and content types, store files outside the web root or on non-executing storage, randomize stored filenames, and serve them with a non-executable content type.`

	ModuleConfirmation = "Confirmed when an uploaded file is accessible and contains the unique scan marker, indicating arbitrary file upload and potential code execution"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
