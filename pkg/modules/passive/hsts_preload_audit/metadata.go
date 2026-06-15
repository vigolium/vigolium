package hsts_preload_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "hsts-preload-audit"
	ModuleName  = "HSTS Preload Audit"
	ModuleShort = "Audits Strict-Transport-Security header for preload readiness"
)

var (
	ModuleDesc = `**What it means:** HTTPS responses lack the Strict-Transport-Security header or it is too weak for browser preload. Gaps include header absent, max-age missing or below one year (31536000), or no includeSubDomains/preload directive, so browsers are not forced onto HTTPS for the host and subdomains.

**How it's exploited:** A network attacker (rogue Wi-Fi, ARP spoofing, proxy) intercepts a first or non-HTTPS request and strips TLS or serves a forged certificate, downgrading to plaintext to read or modify traffic including session cookies.

**Fix:** Send Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on all HTTPS responses and submit the domain to the preload list.`

	ModuleConfirmation = "Confirmed when HSTS header is missing, incomplete, or not preload-ready"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "cryptography", "light"}
)
