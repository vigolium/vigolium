package hsts_preload_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "hsts-preload-audit"
	ModuleName  = "HSTS Preload Audit"
	ModuleShort = "Audits Strict-Transport-Security header for preload readiness"
)

var (
	ModuleDesc = `**What it means:** The site's HTTPS responses are missing the Strict-Transport-Security (HSTS) header, or the header is present but not strong enough for browser preload eligibility. The module reports the specific gaps: header absent, max-age missing or below one year (31536000 seconds), no includeSubDomains directive, or no preload directive. Without a complete HSTS policy, browsers are not forced to use HTTPS for the host and its subdomains.

**How it's exploited:** A network attacker (rogue Wi-Fi, ARP spoofing, malicious proxy) can intercept a victim's first or non-HTTPS request and strip TLS (SSL-stripping) or serve a forged certificate, downgrading the connection to plaintext to read or modify traffic including session cookies. A missing includeSubDomains or preload entry leaves subdomains and the initial visit unprotected.

**Fix:** Send Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on all HTTPS responses and submit the domain to the browser preload list.`

	ModuleConfirmation = "Confirmed when HSTS header is missing, incomplete, or not preload-ready"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"header-security", "cryptography", "light"}
)
