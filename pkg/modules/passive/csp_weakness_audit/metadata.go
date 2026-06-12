package csp_weakness_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "csp-weakness-audit"
	ModuleName  = "CSP Weakness Audit"
	ModuleShort = "Detects weak or unsafe Content-Security-Policy directives"
)

var (
	ModuleDesc = `**What it means:** The response sends a Content-Security-Policy header, but parsing its directives shows configurations that weaken the protection CSP is meant to provide. This module passively flags specific weak directives on HTML responses: unsafe-inline or unsafe-eval in the script source, a wildcard or data:/blob: scheme allowed for scripts, a missing frame-ancestors directive, a missing base-uri restriction, and an object-src that is not locked to 'none'. A flawed CSP gives a false sense of safety because it does not actually contain the attacks it appears to block.

**How it's exploited:** Each weakness reduces the policy's value against real attacks. unsafe-inline, unsafe-eval, wildcard, or data:/blob: script sources let injected payloads run despite CSP, so an XSS bug stays exploitable. A missing frame-ancestors directive permits clickjacking via framing, and an unrestricted base-uri lets a base tag hijack relative resource and form URLs. A permissive object-src can load dangerous plugin content.

**Fix:** Tighten the policy by removing unsafe-inline/unsafe-eval and wildcard/data:/blob: script sources, and set frame-ancestors, base-uri, and object-src to 'none' or trusted values.`

	ModuleConfirmation = "Confirmed when CSP header contains directives that significantly weaken its protection"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"header-security", "misconfiguration", "xss", "light"}
)
