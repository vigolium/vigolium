package xxe_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xxe-generic"
	ModuleName  = "XXE Generic"
	ModuleShort = "Detects XML external entity injection in generic XML endpoints"
)

var (
	ModuleDesc = `**What it means:** An XML/SOAP/XInclude endpoint parses untrusted XML with external entities enabled (XXE). The scanner confirms in-band (a leaked /etc/passwd line or unique marker in the response) or out-of-band, where an external entity/DTD references a unique OAST subdomain the parser fetches - proving resolution even when nothing is reflected (blind XXE).

**How it's exploited:** An attacker references file:///etc/passwd or secrets and reads the leak; blind, an external DTD exfiltrates data or confirms via callback. XXE also escalates to SSRF and DoS.

**Fix:** Disable DOCTYPE and external entity/DTD processing (disallow-doctype-decl, disable external entities and XInclude).`

	ModuleConfirmation = "Confirmed when injected XML entities are expanded and their values appear in the response body, OR when the target's XML parser makes an out-of-band callback to the unique OAST subdomain planted in an external entity/DTD (blind XXE)"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "xxe", "moderate"}
)
