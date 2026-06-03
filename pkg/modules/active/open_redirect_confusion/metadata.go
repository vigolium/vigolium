package open_redirect_confusion

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "open-redirect-confusion"
	ModuleName  = "Open Redirect via URL Parser Confusion"
	ModuleShort = "Detects open redirects that bypass host validation via URL-parser authority confusion"
)

var (
	ModuleDesc = `## Description
Detects open redirect vulnerabilities where a redirect-target validator and the component that
performs the redirect disagree about which host a URL names. By placing the target's own
(trusted) domain and an attacker domain into a single URL using parser divergences — userinfo
(` + "`@`" + `), multiple ` + "`@`" + `, fragment (` + "`#`" + `), whitespace, and backslash —
a value that a same-origin/prefix allowlist accepts still redirects the browser off-origin.

Based on Orange Tsai's "A New Era of SSRF — Exploiting URL Parser in Trending Programming
Languages" (Black Hat USA 2017).

## Notes
- Sibling of the open-redirect module. It does NOT re-emit the payloads that module already
  covers (simple off-origin, ` + "`//`" + `, ` + "`/\\`" + `, host-suffix ` + "`#.`" + ` and
  ` + "`%ff@`" + `); it adds the authority-confusion ladder (decoy@effective, decoy:80@effective,
  multi-@, decoy#@effective, space, backslash).
- In-band detection via the Location/Refresh/meta/JS redirect chain (reused from open-redirect).
- Re-confirmed across multiple rounds with a fresh random attacker domain each round, so a
  coincidental match cannot survive.
- OWASP: Unvalidated Redirects and Forwards.

## References
- https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html`

	ModuleConfirmation = "Confirmed when a URL-parser authority-confusion payload (e.g. trusted-domain@attacker-domain) reproducibly redirects to the attacker domain across multiple rounds with a fresh random domain each round"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"open-redirect", "ssrf", "moderate"}
)
