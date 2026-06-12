package xml_saml_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xml-saml-security"
	ModuleName  = "XML SAML Security"
	ModuleShort = "SAML XML security checks (XXE/DTD)"
)

var (
	ModuleDesc = `**What it means:** The SAML endpoint parses the SAMLRequest/SAMLResponse XML with an unsafe parser that resolves external DTDs and external entities, an XML External Entity (XXE) vulnerability. Because SAML is part of the authentication flow, this exposes a parser at a trusted, often pre-auth boundary.

**How it's exploited:** An attacker submits a SAML message carrying a crafted DOCTYPE or external entity whose SYSTEM identifier points to a server they control. When the target resolves it, the parser can be coerced into fetching attacker-controlled URLs (server-side request forgery into internal networks) and, depending on parser configuration, reading local files or causing denial of service during authentication. This module confirms the flaw out-of-band: it plants a unique OAST callback URL and only reports when the parser actually calls back, so the interaction is unforgeable proof, but it does not itself exfiltrate file contents.

**Fix:** Disable DOCTYPE declarations and external entity/DTD resolution in the SAML XML parser (set FEATURE_SECURE_PROCESSING and reject documents containing a DOCTYPE).`

	ModuleConfirmation = "Confirmed out-of-band: an injected external DTD/entity pointing at a unique OAST callback URL is resolved by the target's XML parser, producing a correlated out-of-band interaction"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xxe", "authentication", "moderate"}
)
