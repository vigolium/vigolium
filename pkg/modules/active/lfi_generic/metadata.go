package lfi_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "lfi-generic"
	ModuleName  = "LFI Generic"
	ModuleShort = "Detects LFI via path traversal payloads"
)

var (
	ModuleDesc = `**What it means:** A request parameter that names a file or path is used to read a file from the server without validation, so attacker-controlled input reaches the filesystem. This Local File Inclusion flaw lets an outsider read files the application was never meant to expose.
**How it's exploited:** The scanner injects path-traversal and PHP-stream payloads (such as ../../etc/passwd, encoded variants, php://filter base64 reads, and data:// wrappers) into likely file or path parameters, and only flags a finding when the response returns 2xx/3xx and contains genuine target-file content not present in the baseline (a real /etc/passwd line, multiple win.ini section headers, web.xml, decoded PHP source, or distinct .env/.htaccess lines). An attacker can read source code, credentials in .env files, /etc/passwd, and other secrets, and PHP wrappers can escalate to remote code execution.
**Fix:** Never pass user input to filesystem APIs; resolve requests against a fixed allowlist of permitted files and reject any traversal sequences or stream wrappers.`

	ModuleConfirmation = "Confirmed when path traversal payloads cause known system file contents (e.g., /etc/passwd) to appear in the response"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"lfi", "injection", "moderate"}
)
