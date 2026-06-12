package express_trust_proxy_misconfig

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "express-trust-proxy-misconfig"
	ModuleName  = "Express Trust Proxy Misconfiguration"
	ModuleShort = "Detects Express trust proxy misconfiguration via X-Forwarded-* header manipulation"
)

var (
	ModuleDesc = `**What it means:** The application trusts attacker-controlled X-Forwarded-* request headers (Proto, Host, For, or Port), typically because an Express trust proxy setting is enabled without restricting it to known proxy addresses. These headers should only be set by a trusted reverse proxy, so honoring them from arbitrary clients lets a user override the protocol, hostname, client IP, or port the app thinks it is serving.

**How it's exploited:** A crafted header makes the app react in a security-relevant way: X-Forwarded-Host reflects into generated URLs, redirect targets, or links (host-header injection, poisoned password-reset links, cache poisoning); X-Forwarded-Port is echoed into URLs and redirects; X-Forwarded-For spoofs the client IP to bypass IP allowlists or rate limiting; X-Forwarded-Proto downgrades the scheme, stripping the cookie Secure flag or altering HTTPS redirects. Each effect is confirmed against a no-header baseline.

**Fix:** Configure Express trust proxy with an explicit list of trusted proxy IPs or a hop count instead of a blanket true, and never use untrusted X-Forwarded-* values for URL generation, redirects, or access decisions.`

	ModuleConfirmation = "Confirmed when X-Forwarded-* header manipulation causes observable behavioral changes such as redirect differences, cookie Secure flag removal, access control bypass, or port injection in generated URLs"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"express", "misconfiguration", "moderate"}
)
