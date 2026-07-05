package xml_saml_security

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xml-saml-security"
	ModuleName  = "XML SAML Security"
	ModuleShort = "SAML XML security checks (XXE + signature verification)"
)

var (
	ModuleDesc = `**What it means:** The SAML endpoint either parses SAMLRequest/SAMLResponse XML with external-entity resolution enabled (XXE at a pre-auth boundary), or accepts an assertion without verifying its XML signature.

**How it's exploited:** An XXE DOCTYPE/entity coerces the parser into fetching attacker URLs (SSRF) or reading files. Separately, if the SP validates assertion content but not the signature, an attacker strips the signature and forges assertions to authenticate as any user.

**Fix:** Disable DOCTYPE/external-entity resolution (FEATURE_SECURE_PROCESSING), and always verify the XML signature against a trusted IdP key, rejecting unsigned or wrapped assertions.`

	ModuleConfirmation = "XXE confirmed out-of-band via a unique OAST callback the parser resolves; signature stripping confirmed when an unsigned-but-valid assertion reproduces the signed baseline response while a wrong-identity control is rejected"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xxe", "authentication", "auth-bypass", "moderate"}
)
