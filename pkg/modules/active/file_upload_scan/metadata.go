package file_upload_scan

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "active-file-upload-scan"
	ModuleName  = "File Upload Scanner"
	ModuleShort = "Tests for arbitrary file upload and execution vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests file upload endpoints for unrestricted file upload vulnerabilities by attempting
to upload files with various bypass techniques. If upload succeeds, attempts to verify
execution of the uploaded file.

## Notes
- Only triggers on multipart/form-data requests with a filename parameter
- Tests 7 probe types: direct extension, double extension, null byte, case variation, magic bytes, SVG XXE, and HTML XSS
- Each probe uses a unique marker for verification
- Reconstructs multipart body preserving non-file fields (CSRF tokens, hidden fields)
- Early abort if first probe returns 400/403/415 (strict validation)
- Attempts to verify upload by fetching common upload directories

## References
- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- https://portswigger.net/web-security/file-upload`

	ModuleConfirmation = "Confirmed when an uploaded file is accessible and contains the unique scan marker, indicating arbitrary file upload and potential code execution"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"rce", "injection", "heavy"}
)
