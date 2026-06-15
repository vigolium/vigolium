package open_redirect_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "open-redirect-confusion"
	ModuleName  = "Open Redirect via URL Parser Confusion"
	ModuleShort = "Detects open redirects that bypass host validation via URL-parser authority confusion"
)

var (
	ModuleDesc = `**What it means:** A redirect-target parameter sends the browser off-site even though the application validates the host, because the validation check and the redirect code parse the URL differently. This open redirect survives prefix-based defenses.

**How it's exploited:** An attacker embeds trusted and attacker domains in one authority via parser quirks like userinfo (trusted@attacker), an extra port, or a backslash. The validator reads the trusted part while the browser navigates to the attacker host, enabling phishing or OAuth/SSO token theft.

**Fix:** Validate redirect targets against a strict exact-hostname allowlist using the same parser that redirects, rejecting any URL with userinfo.`

	ModuleConfirmation = "Confirmed when a URL-parser authority-confusion payload (e.g. trusted-domain@attacker-domain) reproducibly redirects to the attacker domain across multiple rounds with a fresh random domain each round"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"open-redirect", "ssrf", "moderate"}
)
