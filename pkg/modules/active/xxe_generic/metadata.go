package xxe_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xxe-generic"
	ModuleName  = "XXE Generic"
	ModuleShort = "Detects XML external entity injection in generic XML endpoints"
)

var (
	ModuleDesc = `**What it means:** An XML, SOAP, or XInclude endpoint parses untrusted XML with external entity resolution enabled - a classic XML External Entity (XXE) flaw that lets the server read and disclose local files. The scanner confirms in-band: injected entities make targeted content (a /etc/passwd line or unique marker) appear in the response.

**How it's exploited:** An attacker submits XML whose DOCTYPE or XInclude references file:///etc/passwd, config, or secrets, then reads the leaked content. XXE can also escalate to server-side request forgery and denial of service.

**Fix:** Disable DOCTYPE and external entity/DTD processing (FEATURE_SECURE_PROCESSING, disallow-doctype-decl, disable external entities and XInclude).`

	ModuleConfirmation = "Confirmed when injected XML entities are expanded and their values appear in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "xxe", "moderate"}
)
