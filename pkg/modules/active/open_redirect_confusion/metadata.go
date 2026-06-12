package open_redirect_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "open-redirect-confusion"
	ModuleName  = "Open Redirect via URL Parser Confusion"
	ModuleShort = "Detects open redirects that bypass host validation via URL-parser authority confusion"
)

var (
	ModuleDesc = `**What it means:** A redirect-target parameter accepts attacker input that sends the browser to an off-site domain, even though the application validates the target host. The host-validation check and the code that performs the redirect parse the URL differently, so a value the allowlist trusts still redirects elsewhere. This is an open redirect that survives same-origin or prefix-based defenses.

**How it's exploited:** An attacker crafts a URL that embeds the trusted domain and an attacker domain in one authority, using parser quirks such as userinfo (trusted@attacker), an extra port (trusted:80@attacker), multiple @ signs, a fragment, whitespace, or a backslash. The validator reads the trusted part while the browser navigates to the attacker host, enabling convincing phishing, OAuth/SSO token theft via redirect_uri abuse, or chaining into SSRF where the same parsing gap exists server-side.

**Fix:** Validate redirect targets with a strict allowlist of exact hostnames using the same parser that performs the redirect, and reject any URL with userinfo, embedded credentials, or off-origin authorities.`

	ModuleConfirmation = "Confirmed when a URL-parser authority-confusion payload (e.g. trusted-domain@attacker-domain) reproducibly redirects to the attacker domain across multiple rounds with a fresh random domain each round"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"open-redirect", "ssrf", "moderate"}
)
