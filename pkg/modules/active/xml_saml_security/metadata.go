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
- Injects an external DTD / external entity into SAMLRequest/SAMLResponse XML,
  with the SYSTEM identifier pointing at a unique out-of-band (OAST) callback URL.
- Confirmation is purely out-of-band: a finding is only emitted when the target's
  XML parser actually resolves the injected reference and calls back to the OAST
  server. The per-payload subdomain is unguessable, so a correlated interaction is
  unforgeable proof the parser loads external entities.
- Requires an OAST/interaction server to be configured; without one the module
  no-ops (it does not fall back to a response-shape heuristic, which is FP-prone).

## References
- https://portswigger.net/research/saml-roulette-the-hacker-always-wins
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing`

	ModuleConfirmation = "Confirmed out-of-band: an injected external DTD/entity pointing at a unique OAST callback URL is resolved by the target's XML parser, producing a correlated out-of-band interaction"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xxe", "authentication", "moderate"}
)
