package nextjs_version_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

// advisory represents a known Next.js security advisory.
type advisory struct {
	cve         string
	title       string
	description string
	severity    severity.Severity
	// affectedBelow is the version that fixes the issue (exclusive upper bound).
	// Versions below this are affected.
	affectedBelow string
	// affectedAbove is the minimum affected version (inclusive lower bound).
	// Versions at or above this are affected (combined with affectedBelow).
	affectedAbove string
	reference     string
}

// knownAdvisories is the list of known Next.js security advisories.
var knownAdvisories = []advisory{
	{
		cve:           "CVE-2025-29927",
		title:         "Middleware Auth Bypass",
		description:   "Authorization bypass via x-middleware-subrequest header allows skipping middleware-based authentication checks",
		severity:      severity.Critical,
		affectedBelow: "15.2.3",
		affectedAbove: "11.0.0",
		reference:     "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
	},
	{
		cve:           "CVE-2024-34351",
		title:         "SSRF via Server Actions",
		description:   "Server-Side Request Forgery via Host header in Server Actions redirect responses",
		severity:      severity.High,
		affectedBelow: "14.1.1",
		affectedAbove: "13.4.0",
		reference:     "https://github.com/advisories/GHSA-fr5h-rqp8-mj6g",
	},
	{
		cve:           "CVE-2024-46982",
		title:         "Cache Poisoning DoS",
		description:   "Cache poisoning via stale cached pages when using pages router and i18n with specific configurations",
		severity:      severity.High,
		affectedBelow: "14.2.10",
		affectedAbove: "13.0.0",
		reference:     "https://github.com/advisories/GHSA-gp8f-8m3g-qvj9",
	},
	{
		cve:           "CVE-2024-39693",
		title:         "Server Actions DoS via Large Payload",
		description:   "Denial of Service via crafted HTTP request to Server Actions endpoint with large body",
		severity:      severity.High,
		affectedBelow: "14.1.1",
		affectedAbove: "13.4.0",
		reference:     "https://github.com/advisories/GHSA-fq54-2j52-jc42",
	},
	{
		cve:           "CVE-2024-51479",
		title:         "Authorization Bypass via Parallel Routes",
		description:   "Pages served from the .next/server/pages directory may bypass authorization checks due to incorrect handling of parallel routes",
		severity:      severity.High,
		affectedBelow: "14.2.15",
		affectedAbove: "14.0.0",
		reference:     "https://github.com/advisories/GHSA-7gfc-8cq8-jh5f",
	},
	{
		cve:           "CVE-2024-56332",
		title:         "DoS via Middleware Redirect Loop",
		description:   "Denial of Service caused by uncontrolled resource consumption via recursive middleware redirects",
		severity:      severity.Medium,
		affectedBelow: "14.2.15",
		affectedAbove: "11.0.0",
		reference:     "https://github.com/advisories/GHSA-7m27-7ghc-44w9",
	},
}
