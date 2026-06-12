package crlf_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "crlf-injection"
	ModuleName  = "CRLF Injection"
	ModuleShort = "Detects CRLF injection"
)

var (
	ModuleDesc = `**What it means:** The application reflects a URL parameter into HTTP response headers without stripping carriage-return and line-feed (CRLF) characters, so an attacker can inject new header lines. This module proved it by smuggling an attacker-controlled Set-Cookie header through the parameter and confirming it appeared in the response headers across multiple rounds with fresh random values, which rules out coincidence.
**How it's exploited:** An attacker crafts a link whose parameter contains CRLF sequences (raw or encoded as %0d%0a / %250d%250a) followed by a malicious header. The server emits it verbatim, letting the attacker set arbitrary response headers, plant or fixate session cookies, split the response to poison shared caches, or inject content that leads to cross-site scripting against anyone who follows the link.
**Fix:** Reject or URL-encode CR and LF characters in any user input before placing it in a response header, and use a framework header API that forbids embedded line breaks.`

	ModuleConfirmation = "Confirmed when injected CRLF sequences appear in HTTP response headers, indicating header injection"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"crlf", "injection", "moderate"}
)
