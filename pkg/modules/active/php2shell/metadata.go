package php2shell

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "php2shell"
	ModuleName  = "php2shell Multipart Parser Crash"
	ModuleShort = "Flags PHP hosts whose multipart parser crashes on deeply nested array keys (php2shell, CVE-2026-109618 / CVE-2026-109619)"
)

var (
	ModuleDesc = `**What it means:** PHP's multipart/form-data parser on this host crashed on a body of deeply nested array field names (php2shell). Unpatched PHP corrupts memory here. A patched PHP with a low memory_limit can crash the same way, so treat this as a lead to verify against the installed version.

**How it's exploited:** An unauthenticated attacker sends crafted multipart requests to any PHP script, crashing workers at will and, on affected builds, reaching remote code execution.

**Fix:** Upgrade PHP to 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later (or the vendor backport), and cap request body size at the web server.`

	ModuleConfirmation = "Reported when a nested-key multipart probe (1, 8 or 20 MiB) makes the PHP handler fail where a 42-byte multipart control succeeded: an in-band memory-exhausted fatal error, an empty HTTP 500, or a PHP-FPM worker death (502/503/504 or an empty 200). Hosts advertising a patched PHP release are skipped"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	// "php" gates the module on hosts a PHP fingerprint marked (re-checked fail
	// closed in the scan). risk:high: each tested path takes up to ~29 MiB of
	// upload and can kill a PHP-FPM worker, so a broad selection runs it only at
	// --intensity deep or with --allow-risky-payloads.
	ModuleTags = []string{"php", "cve", "rce", "dos", "intrusive", "risk:high"}
)
