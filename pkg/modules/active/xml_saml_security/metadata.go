package xml_saml_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xml-saml-security"
	ModuleName  = "XML SAML Security"
	ModuleShort = "SAML XML security checks (XXE/DTD)"
)

var (
	ModuleDesc = `**What it means:** The SAML endpoint parses SAMLRequest/SAMLResponse XML with a parser that resolves external DTDs and entities - an XML External Entity (XXE) flaw at a trusted, pre-auth boundary.

**How it's exploited:** An attacker submits a SAML message with a crafted DOCTYPE or entity whose SYSTEM identifier points to their server. The parser can be coerced into fetching attacker URLs (server-side request forgery) and, per config, reading files or causing denial of service. The scanner confirms out-of-band via a unique OAST callback.

**Fix:** Disable DOCTYPE declarations and external entity/DTD resolution (set FEATURE_SECURE_PROCESSING and reject documents with a DOCTYPE).`

	ModuleConfirmation = "Confirmed out-of-band: an injected external DTD/entity pointing at a unique OAST callback URL is resolved by the target's XML parser, producing a correlated out-of-band interaction"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xxe", "authentication", "moderate"}
)
