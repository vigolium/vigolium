package express_trust_proxy_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-trust-proxy-misconfig"
	ModuleName  = "Express Trust Proxy Misconfiguration"
	ModuleShort = "Detects Express trust proxy misconfiguration via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `**What it means:** The app trusts attacker-controlled X-Forwarded-* headers (Proto, Host, For, Port), typically because Express trust proxy is enabled without restricting to known proxies, letting any client override the protocol, hostname, client IP, or port.

**How it's exploited:** X-Forwarded-Host reflects into URLs and redirects (host-header injection, poisoned password-reset links, cache poisoning); X-Forwarded-For spoofs the client IP to bypass allowlists or rate limiting; X-Forwarded-Proto downgrades the scheme, stripping the Secure flag.

**Fix:** Set Express trust proxy to explicit proxy IPs or a hop count, not a blanket true, and never use untrusted X-Forwarded-* values for URLs, redirects, or access decisions.`

	ModuleConfirmation = "Confirmed when X-Forwarded-* header manipulation causes observable behavioral changes such as redirect differences, cookie Secure flag removal, access control bypass, or port injection in generated URLs"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "misconfiguration", "moderate"}
)
