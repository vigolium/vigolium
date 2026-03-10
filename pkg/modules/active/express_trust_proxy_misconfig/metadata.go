package express_trust_proxy_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-trust-proxy-misconfig"
	ModuleName  = "Express Trust Proxy Misconfiguration"
	ModuleShort = "Detects Express trust proxy misconfiguration via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `## Description
Detects Express.js trust proxy misconfiguration by sending X-Forwarded-* header variants
and comparing responses against a baseline to identify behavioral changes.

When Express.js has ` + "`trust proxy`" + ` enabled without proper validation, attackers can
manipulate X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-For, and X-Forwarded-Port
headers to cause protocol confusion, IP-based access control bypass, and port injection.

## Notes
- X-Forwarded-Proto can cause redirect loops or strip Secure flags from cookies
- X-Forwarded-Host can be trusted for URL generation, leading to host-based attacks
- X-Forwarded-For can bypass IP-based rate limiting or access controls
- X-Forwarded-Port can inject unexpected ports into generated URLs and redirects
- Compares each probe response against a baseline to detect behavioral changes

## References
- https://expressjs.com/en/guide/behind-proxies.html
- https://expressjs.com/en/api.html#trust.proxy.options.table
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection`

	ModuleConfirmation = "Confirmed when X-Forwarded-* header manipulation causes observable behavioral changes such as redirect differences, cookie Secure flag removal, access control bypass, or port injection in generated URLs"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "misconfiguration", "moderate"}
)
