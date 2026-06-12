package xxe_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xxe-generic"
	ModuleName  = "XXE Generic"
	ModuleShort = "Detects XML external entity injection in generic XML endpoints"
)

var (
	ModuleDesc = `**What it means:** An XML, SOAP, or XInclude endpoint parses untrusted XML with external entity resolution enabled, so attacker-declared entities are expanded by the server. This is a classic XML External Entity (XXE) flaw that lets an attacker make the server read local files and disclose their contents. The scanner confirms the in-band case: it injects entity declarations and verifies that the targeted file content (a /etc/passwd root line, Windows win.ini sections, or a unique internal-entity marker) appears in the response and was absent from the original baseline, after rejecting WAF, 404, and redirect pages.
**How it's exploited:** An attacker submits crafted XML whose DOCTYPE or XInclude directive references file:///etc/passwd, application config, secrets, or source files, then reads the leaked content reflected in the response. Beyond local file disclosure, XXE can be escalated to server-side request forgery, internal port scanning, and denial of service.
**Fix:** Disable DOCTYPE and external entity/DTD processing in the XML parser (set FEATURE_SECURE_PROCESSING, disallow-doctype-decl, and disable external general/parameter entities and XInclude).`

	ModuleConfirmation = "Confirmed when injected XML entities are expanded and their values appear in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "xxe", "moderate"}
)
