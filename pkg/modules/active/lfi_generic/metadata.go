package lfi_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "lfi-generic"
	ModuleName  = "LFI Generic"
	ModuleShort = "Detects LFI via path traversal payloads"
)

var (
	ModuleDesc = `**What it means:** A file or path parameter reaches the filesystem unvalidated, so an outsider reads files never meant to be served (Local File Inclusion).

**How it's exploited:** Traversal and php://filter reads flag only file content absent from the baseline. data://, expect:// and php://input probes print the product of two random numbers never sent; that product proves code execution (Critical). Attackers read source, .env credentials and /etc/passwd, or run code.

**Fix:** Never pass user input to filesystem APIs; resolve against a fixed allowlist and reject traversal sequences and wrappers.`

	ModuleConfirmation = "Confirmed when path traversal payloads cause known system file contents (e.g., /etc/passwd) to appear in the response; reported as code execution when a wrapper probe's computed product, absent from the request and the baseline, appears in the response"
	// High, not Critical: the file-read oracle proves a file was read, not that
	// the read reaches code execution. A confirmed execution probe raises its
	// own finding to Critical (execFindingInfo). Critical also left no
	// headroom to distinguish a confirmed /etc/passwd read from the weaker
	// docroot-relative results, which now downgrade to Info via
	// modkit.DocrootFetchInfo. Sibling lfi-path-traversal already reports High.
	ModuleSeverity   = severity.High
	ModuleConfidence = severity.Certain
	ModuleTags       = []string{"lfi", "injection", "moderate"}
)
