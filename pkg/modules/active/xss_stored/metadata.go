package xss_stored

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "xss-stored"
	ModuleName  = "Stored XSS (browser-confirmed)"
	ModuleShort = "Injects a canary, then confirms it executes on a later retrieval of the page"
)

var (
	ModuleDesc = `## Description
Detects stored (persistent) XSS. A unique canary payload is written through an insertion
point, the page is then re-fetched with a clean request, and if the canary surfaces in that
separate response it must have been stored. Execution is then confirmed in a headless
browser, so a finding reflects a payload that both persisted and ran.

## Notes
- Distinguishes stored from reflected: the retrieval request never carries the payload, so a
  reflected-only value cannot trigger a finding
- Retrieval is currently the same URL the value was submitted to; display pages on a
  different URL are not yet covered
- Confirmation replays the scan session (cookies) so behind-login pages still render

## References
- https://owasp.org/www-community/attacks/xss/#stored-xss-attacks`

	ModuleConfirmation = "Confirmed when an injected payload persists and executes JavaScript on a subsequent retrieval of the page"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "xss", "stored"}
)
