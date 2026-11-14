package aem_ssrf

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "aem-ssrf"
	ModuleName  = "AEM SSRF-Capable Proxy Servlet Exposure"
	ModuleShort = "Detects reachable AEM proxy/fetch servlets known for SSRF (ContentInsight reporting proxy, opensocial/shindig, SalesforceSecretServlet, accesstoken/verify) without firing an out-of-band request"
)

var (
	ModuleDesc = `**What it means:** An AEM servlet that fetches a caller-supplied URL server-side — the ContentInsight reporting proxy, opensocial/shindig, SalesforceSecretServlet (CVE-2018-12809), or accesstoken/verify (CVE-2025-54249) — is reachable. Detection-only: it confirms the servlet is a specific mount but supplies no URL, so no request is triggered (Tentative).

**How it's exploited:** An attacker points the url/auth_url parameter at internal services the AEM host can reach but the internet cannot.

**Fix:** Block these proxy servlets at the dispatcher, apply Adobe's patches, and restrict the destinations they may fetch.`

	ModuleConfirmation = "Confirmed when a known SSRF-capable AEM servlet responds as a specific mount (a random sibling 404s) and reproduces, without any SSRF request being sent"
	ModuleSeverity     = severity.Suspect
	ModuleConfidence   = severity.Tentative
	ModuleTags         = []string{"aem", "adobe", "ssrf", "exposure", "cms", "moderate"}
)
