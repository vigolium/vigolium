package sqli_boolean_blind

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "sqli-boolean-blind"
	ModuleName  = "Blind SQL Injection (Boolean-Based)"
	ModuleShort = "Detects boolean-based blind SQL injection vulnerabilities"
)

var (
	ModuleDesc = `## Description
Tests for boolean-based blind SQL injection by sending paired TRUE/FALSE payloads and comparing
response differentials. Uses triple-verification to minimize false positives: TRUE and FALSE
payloads must produce consistently different responses across multiple requests.

## Notes
- Sends TRUE and FALSE payload pairs to each injection point
- Compares responses with a difflib-style token-similarity ratio (quick_ratio)
  over normalized bodies, so detection survives dynamic content (CSRF tokens,
  timestamps, reflected input) and keys on content-level differentials
- Only reports differentials between HTTP 200 responses (baseline, TRUE and FALSE
  must all be 200); a 200↔3xx/4xx/5xx status flip is rejected as a false positive
- Requires a large TRUE/FALSE body-size difference (substantial absolute and
  relative delta), so marginal/dynamic differences are not reported
- A pair is only a signal when each branch's similarity to the baseline diverges
  past a tolerance (mirrors sqlmap's DIFF_TOLERANCE)
- Triple-verification: confirms TRUE/FALSE/baseline are ratio-stable across retries
- Multi-round, multi-factor confirmation before reporting: detects the working
  AND/OR oracle, replays it over several rounds with fresh random operands and
  alternating comparison operators (=, <>), requires each branch to stay
  ratio-stable, and runs an invalid-syntax probe that must not render the TRUE
  page — rejecting endpoints that ignore SQL validity
- Tests string context, numeric context, WAF bypass, and a randomized boundary
  matrix (prefix/suffix × clause) with random integers to defeat 1=1 special-casing
- Uses NoRedirects to capture TRUE/FALSE differential before redirect

## References
- https://owasp.org/www-community/attacks/Blind_SQL_Injection
- https://portswigger.net/web-security/sql-injection/blind`

	ModuleConfirmation = "Confirmed when TRUE payloads consistently produce different responses from FALSE payloads across multiple verification requests"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"injection", "sqli", "heavy"}
)
