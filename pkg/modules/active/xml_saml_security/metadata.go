package xml_saml_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xml-saml-security"
	ModuleName  = "XML SAML Security"
	ModuleShort = "SAML XML security checks (XXE/DTD)"
)

var (
	ModuleDesc = `## Description
Detects unsafe XML transformation in SAML processing, including XXE (XML External Entity)
and DTD (Document Type Definition) injection vulnerabilities.

## Notes
- Tests XML parameters for entity expansion and external entity loading
- Targets SAML-specific XML processing endpoints

## References
- https://portswigger.net/research/saml-roulette-the-hacker-always-wins
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing`

	ModuleConfirmation = "Confirmed when injected XML entities are processed and expanded, or DTD declarations are loaded by the server"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xxe", "authentication", "moderate"}
)
