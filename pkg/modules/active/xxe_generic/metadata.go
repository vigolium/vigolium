package xxe_generic

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xxe-generic"
	ModuleName  = "XXE Generic"
	ModuleShort = "Detects XML external entity injection in generic XML endpoints"
)

var (
	ModuleDesc = `## Description
Detects XML External Entity (XXE) injection vulnerabilities in endpoints that accept
XML input by injecting entity declarations and checking for entity expansion.

## Notes
- Tests XML body parameters for entity expansion
- Injects external entity declarations targeting known files
- Checks for entity value reflection in response body
- Complements the XML SAML Security module for non-SAML XML endpoints

## References
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- https://portswigger.net/web-security/xxe`

	ModuleConfirmation = "Confirmed when injected XML entities are expanded and their values appear in the response body"
	ModuleSeverity     = severity.Critical
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "xxe", "moderate"}
)
