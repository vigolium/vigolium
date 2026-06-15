package crlf_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crlf-injection"
	ModuleName  = "CRLF Injection"
	ModuleShort = "Detects CRLF injection"
)

var (
	ModuleDesc = `**What it means:** The application reflects a URL parameter into HTTP response headers without stripping carriage-return/line-feed (CRLF) characters, letting an attacker inject new header lines. Proven by smuggling a Set-Cookie header through the parameter.

**How it's exploited:** An attacker crafts a link whose parameter holds CRLF sequences (raw or encoded %0d%0a) plus a malicious header. The server emits it verbatim, letting the attacker set arbitrary headers, fixate session cookies, poison caches, or inject XSS.

**Fix:** Reject or URL-encode CR and LF in user input before it reaches a response header, and use a header API that forbids line breaks.`

	ModuleConfirmation = "Confirmed when injected CRLF sequences appear in HTTP response headers, indicating header injection"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"crlf", "injection", "moderate"}
)
