package nextjs_version_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

type versionRange struct {
	introduced string // inclusive
	fixed      string // exclusive upper bound / first patched version
}

// advisory preserves branch-specific affected intervals. Next.js backports
// fixes independently across majors/minors, so collapsing an advisory to one
// broad >=min,<max interval incorrectly marks patched older branches vulnerable.
type advisory struct {
	cve            string
	title          string
	description    string
	severity       severity.Severity
	affectedRanges []versionRange
	reference      string
	prerequisites  []string
}

var knownAdvisories = []advisory{
	{
		cve:         "CVE-2025-29927",
		title:       "Middleware Auth Bypass",
		description: "Authorization bypass via x-middleware-subrequest header allows skipping middleware-based authentication checks",
		severity:    severity.Critical,
		affectedRanges: []versionRange{
			{introduced: "12.0.0", fixed: "12.3.5"},
			{introduced: "13.0.0", fixed: "13.5.9"},
			{introduced: "14.0.0", fixed: "14.2.25"},
			{introduced: "15.0.0", fixed: "15.2.3"},
		},
		reference:     "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
		prerequisites: []string{"authorization enforced in Next.js middleware", "deployment not otherwise protected by its hosting provider"},
	},
	{
		cve:         "CVE-2024-34351",
		title:       "SSRF via Server Actions",
		description: "Server-Side Request Forgery via Host header in Server Actions redirect responses",
		severity:    severity.High,
		affectedRanges: []versionRange{
			{introduced: "13.4.0", fixed: "14.1.1"},
		},
		reference: "https://github.com/advisories/GHSA-fr5h-rqp8-mj6g",
		prerequisites: []string{
			"self-hosted deployment", "Server Actions in use", "a Server Action redirects to a relative path",
		},
	},
	{
		cve:         "CVE-2024-46982",
		title:       "Cache Poisoning DoS",
		description: "Cache poisoning of a non-dynamic server-side rendered Pages Router route",
		severity:    severity.High,
		affectedRanges: []versionRange{
			{introduced: "13.5.1", fixed: "13.5.7"},
			{introduced: "14.0.0", fixed: "14.2.10"},
		},
		reference:     "https://github.com/advisories/GHSA-gp8f-8m3g-qvj9",
		prerequisites: []string{"Pages Router in use", "non-dynamic SSR route", "deployment not hosted on Vercel"},
	},
	{
		cve:         "CVE-2024-39693",
		title:       "Denial of Service",
		description: "Crafted requests can crash affected Next.js releases",
		severity:    severity.High,
		affectedRanges: []versionRange{
			{introduced: "13.3.1", fixed: "13.5.0"},
		},
		reference: "https://github.com/advisories/GHSA-fq54-2j52-jc42",
	},
	{
		cve:         "CVE-2024-51479",
		title:       "Authorization Bypass via Middleware Pathname",
		description: "Pathname-based authorization in middleware can be bypassed",
		severity:    severity.High,
		affectedRanges: []versionRange{
			{introduced: "9.5.5", fixed: "14.2.15"},
		},
		reference:     "https://github.com/advisories/GHSA-7gfc-8cq8-jh5f",
		prerequisites: []string{"pathname-based authorization in middleware", "deployment not otherwise protected by its hosting provider"},
	},
	{
		cve:         "CVE-2024-56332",
		title:       "Server Actions Denial of Service",
		description: "Malformed requests can leave Server Action invocations hanging",
		severity:    severity.Medium,
		affectedRanges: []versionRange{
			{introduced: "13.0.0", fixed: "13.5.8"},
			{introduced: "14.0.0", fixed: "14.2.21"},
			{introduced: "15.0.0", fixed: "15.1.2"},
		},
		reference:     "https://github.com/advisories/GHSA-7m27-7ghc-44w9",
		prerequisites: []string{"Server Actions in use", "no effective long-running request timeout or equivalent protection"},
	},
}
