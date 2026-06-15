package csp_weakness_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csp-weakness-audit"
	ModuleName  = "CSP Weakness Audit"
	ModuleShort = "Detects weak or unsafe Content-Security-Policy directives"
)

var (
	ModuleDesc = `**What it means:** A Content-Security-Policy header is present but its directives weaken the protection it should provide - unsafe-inline/unsafe-eval, wildcard or data:/blob: script sources, a missing frame-ancestors or base-uri, or an object-src not set to 'none'.

**How it's exploited:** Weak script sources let injected payloads run despite CSP, so an XSS bug stays exploitable. Missing frame-ancestors permits clickjacking, an open base-uri lets a base tag hijack relative URLs, and a loose object-src can load dangerous plugin content.

**Fix:** Remove unsafe-inline/unsafe-eval and wildcard/data:/blob: script sources; set frame-ancestors, base-uri, and object-src to 'none' or trusted values.`

	ModuleConfirmation = "Confirmed when CSP header contains directives that significantly weaken its protection"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"header-security", "misconfiguration", "xss", "light"}
)
