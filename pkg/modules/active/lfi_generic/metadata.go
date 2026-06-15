package lfi_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "lfi-generic"
	ModuleName  = "LFI Generic"
	ModuleShort = "Detects LFI via path traversal payloads"
)

var (
	ModuleDesc = `**What it means:** A request parameter naming a file or path is read from the server without validation, so attacker input reaches the filesystem. This Local File Inclusion flaw lets an outsider read files never meant to be served.

**How it's exploited:** The scanner injects path-traversal and PHP-stream payloads (../../etc/passwd, php://filter base64 reads, data:// wrappers), flagging only on genuine target-file content absent from the baseline. An attacker reads source code, .env credentials, and /etc/passwd, and PHP wrappers can reach code execution.

**Fix:** Never pass user input to filesystem APIs; resolve against a fixed allowlist and reject traversal sequences and wrappers.`

	ModuleConfirmation = "Confirmed when path traversal payloads cause known system file contents (e.g., /etc/passwd) to appear in the response"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"lfi", "injection", "moderate"}
)
