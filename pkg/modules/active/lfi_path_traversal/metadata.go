package lfi_path_traversal

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "lfi-path-traversal"
	ModuleName  = "LFI Path Traversal"
	ModuleShort = "Detects LFI via advanced path traversal, null bytes, encoding bypass, and multi-marker confirmation"
)

var (
	ModuleDesc = `## Description
Detects Local File Inclusion vulnerabilities using advanced path traversal techniques
including null byte injection, double URL encoding, Unicode bypass characters, and
multi-marker confirmation to reduce false positives.

## Notes
- Complements lfi_generic with deeper traversal payloads and stronger confirmation
- Requires at least 2 markers to match in fuzzed response (not present in baseline)
- Body length delta check prevents matching on trivially similar responses
- Pre-filters insertion points by file-like parameter names and path-like values

## References
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion`

	ModuleConfirmation = "Confirmed when multiple file content markers appear in the response after injecting path traversal payloads and are absent from the baseline response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"lfi", "injection", "heavy"}
)
