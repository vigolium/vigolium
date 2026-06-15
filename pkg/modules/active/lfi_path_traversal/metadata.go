package lfi_path_traversal

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "lfi-path-traversal"
	ModuleName  = "LFI Path Traversal"
	ModuleShort = "Detects LFI via advanced path traversal, null bytes, encoding bypass, and multi-marker confirmation"
)

var (
	ModuleDesc = `**What it means:** A parameter naming a file or path lets an attacker escape the intended directory and read arbitrary server files (Local File Inclusion / path traversal). Confirmed when real OS file contents (/etc/passwd, win.ini) appear in the response but not the baseline.

**How it's exploited:** An attacker supplies ../../../../etc/passwd, optionally with encoding tricks to defeat filters, exposing credentials and secrets (.env, .git) and reaching RCE when included content is executed.

**Fix:** Never pass user input into filesystem paths; use a fixed allow-list, reject traversal and absolute paths, and confirm the resolved path stays inside the base directory.`

	ModuleConfirmation = "Confirmed when multiple file content markers appear in the response after injecting path traversal payloads and are absent from the baseline response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"lfi", "injection", "heavy"}
)
