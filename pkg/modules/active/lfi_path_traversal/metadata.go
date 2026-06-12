package lfi_path_traversal

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "lfi-path-traversal"
	ModuleName  = "LFI Path Traversal"
	ModuleShort = "Detects LFI via advanced path traversal, null bytes, encoding bypass, and multi-marker confirmation"
)

var (
	ModuleDesc = `**What it means:** A request parameter that names a file or path lets an attacker break out of the intended directory and make the server read arbitrary files from its filesystem (Local File Inclusion / path traversal). This module confirmed the issue by injecting traversal payloads and observing real OS file contents (such as /etc/passwd or windows/win.ini) returned in the response that were absent from the original baseline.

**How it's exploited:** An attacker supplies values like ../../../../etc/passwd, optionally with null-byte, double-URL-encoding, Unicode, or overlong-UTF-8 tricks to defeat filters, and the application returns the file. This exposes credentials, configuration, source code, secrets (.env, .git, web.xml), and system files, and can escalate to remote code execution if attacker-controlled content (logs, /proc/self/environ) is included and executed.

**Fix:** Never pass user input into filesystem paths; map requests to a fixed allow-list of identifiers, reject traversal sequences and absolute paths, and canonicalize then confirm the resolved path stays inside an intended base directory.`

	ModuleConfirmation = "Confirmed when multiple file content markers appear in the response after injecting path traversal payloads and are absent from the baseline response"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"lfi", "injection", "heavy"}
)
