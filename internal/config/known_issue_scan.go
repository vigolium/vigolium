package config

import (
	"fmt"
	"strings"
)

// KnownIssueScanConfig holds configuration for known-issue scan (nuclei library).
type KnownIssueScanConfig struct {
	Tags         []string `yaml:"tags"`          // nuclei template tags (empty = all)
	ExcludeTags  []string `yaml:"exclude_tags"`  // tags to exclude
	Severities   []string `yaml:"severities"`    // filter severities (empty = all)
	TemplatesDir string   `yaml:"templates_dir"` // custom templates path
	// SeverityOverrides remaps the severity a finding is recorded with, keyed by
	// nuclei template ID (case-insensitive). The override is applied after a match
	// but before output/persistence, so the finding, console output, and severity
	// counts all reflect the remapped value. Use it to right-size noisy or
	// context-dependent templates without forking the upstream template (which
	// reverts on `nuclei -update-templates`). Example:
	//
	//	known_issue_scan:
	//	  severity_overrides:
	//	    config-json-exposure-fuzz: medium
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	EnrichTargets     bool              `yaml:"enrich_targets"` // enrich known-issue scan targets with paths discovered in previous phases (increases coverage but can slow down scans)
	// GroupByValue collapses findings that repeat the same extracted value across
	// many URLs (e.g. one leaked secret reported once per page) into a single
	// finding. It applies both to the stored/reported findings (a post-phase
	// merge pass) and to the live console output (one line per unique value).
	GroupByValue *FindingGroupingConfig `yaml:"group_by_value,omitempty"`
}

// FindingGroupingConfig controls value-based grouping of findings that share an
// identical extracted value across many URLs — the classic example being one
// leaked API key surfaced on dozens of pages, which would otherwise be reported
// once per page.
type FindingGroupingConfig struct {
	// Enabled turns value-based grouping on.
	Enabled bool `yaml:"enabled"`
	// PerHost keeps the same value found on different hosts as separate findings.
	// When false, grouping is project-wide regardless of host.
	PerHost bool `yaml:"per_host"`
	// Tags, when non-empty, restricts grouping to findings carrying at least one
	// of these tags (case-insensitive). Empty groups any finding that repeats an
	// identical extracted value — the value-identity (plus module + severity) is
	// itself the guardrail against merging unrelated findings.
	Tags []string `yaml:"tags"`
	// ByModule lists module IDs whose findings collapse to a single finding per
	// (module, severity[, host]) regardless of the per-URL extracted value. Use
	// it for modules that fire once per asset where the differing value is noise,
	// not signal — e.g. sourcemap-detect (a distinct .map filename per JS/CSS
	// bundle), the static source-analysis sink/audit family (one snippet context
	// per matched file), and per-response hygiene checks (one finding per page).
	// Module identity (plus severity, so a Low "sourcemap advertised" never merges
	// with a High "full source exposed") is the guardrail; the Tags gate does not
	// apply to these modules. See perAssetGroupModules for the shipped default.
	ByModule []string `yaml:"by_module"`
	// ByRule lists module IDs whose findings collapse per (module, rule_name,
	// severity[, host]) — like ByModule but with the rule (module_name) kept in the
	// key, so a module whose one ID fronts many rules folds repeats of a single
	// rule while keeping different rules apart. The shipped default is
	// secret-detect: one Kingfisher rule (e.g. "Looker Client ID") matching every
	// content hash in a minified bundle's chunk-hash map collapses to one finding
	// (all values unioned on), while a genuinely different secret keeps its row.
	// See perRuleGroupModules for the shipped default.
	ByRule []string `yaml:"by_rule"`
	// MaxURLs caps how many distinct matched URLs are retained on the survivor
	// finding (0 = unlimited), bounding MatchedAt on very noisy sites.
	MaxURLs int `yaml:"max_urls"`
}

// perAssetGroupModules are the modules whose findings collapse to a single
// finding per (module, severity, host) regardless of their per-URL extracted
// value, because they fire once per asset (JS/CSS bundle, page, or response) and
// the differing value is noise, not signal. When such a group is collapsed the
// distinct extracted values are unioned onto the survivor (see
// GroupFindingsByValue), so the merged finding still lists every matched value and
// URL — just as one finding instead of dozens. Several classes live here:
//
//   - Static source-analysis leads — "this sink / misconfig / boundary-violation
//     pattern exists somewhere on this host." On an SPA these fire once per JS
//     bundle, producing dozens of near-identical Low findings that differ only in
//     which file/snippet matched.
//   - Per-response client-side hygiene — one finding per page that sets a cookie
//     (or per response), which on a large site is one finding per crawled URL.
//   - Informational recon & fingerprinting — Info/Low observations that fire once
//     per response (tech-stack fingerprints, cloud/recon harvest, endpoint/param
//     enumeration, response header hygiene). On a crawl of any size these produce
//     one near-identical row per URL; the operator wants "this host runs Laravel"
//     or "these params reflect" once, with the affected URLs/values attached.
//
// Collapsing them per host keeps the merged survivor's MatchedAt URL list (capped
// by MaxURLs) so the operator can still see every affected asset.
//
// Deliberately excluded: modules where each distinct extracted value IS the
// signal and deserves its own triage row — secret-bearing source analysis
// (env-secret-exposure) and content-disclosure detectors (base64-data-detect,
// error-message-detect, info-disclosure-detect, directory-listing-detect) — those
// stay value-grouped so two different leaks remain two findings. (HSTS preload
// audit already fires once per host via ScanPerHost, so it needs no entry.)
//
// secret-detect is NOT here either, but it is not plain value-grouped: it lands
// in perRuleGroupModules (by-rule grouping), which folds repeats of one Kingfisher
// rule on a host while keeping different rules apart — the right middle ground for
// a module whose single id fronts many rules.
var perAssetGroupModules = []string{
	// Asset enumeration: a distinct .map filename per JS/CSS bundle.
	"sourcemap-detect",
	// Informational JS beautification: one Info finding per unminified JS bundle,
	// keyed only by its distinct URL — collapse per host, keeping every URL.
	"js-beautify",
	// Static sink / DOM-XSS source analysis: one snippet context per matched file.
	"unsafe-html-sink",
	"dom-xss-taint",
	"dom-xss-detect",
	"javascript-uri-sink",
	"insecure-token-storage",
	// postMessage handler/usage analysis: one listener/call site per JS bundle. The
	// Info "handler detected" lead fires once per bundle (pure source-analysis noise);
	// its higher-severity siblings (sent-to-wildcard-origin, no-origin-validation) key
	// separately by severity and still collapse per host with sinks kept as evidence.
	"postmessage-handler-detect",
	// Framework / build / SSR config & boundary audits: the issue class is the
	// finding; which file or route surfaced it is noise.
	"build-misconfig-detect",
	"client-auth-guard",
	"cache-data-leak",
	"nextjs-config-audit",
	"nextjs-dynamic-param-audit",
	"nuxt-config-audit",
	"nextauth-config-audit",
	"server-action-auth",
	"server-action-bind-audit",
	"server-action-input-audit",
	"server-only-boundary-audit",
	"ssr-data-exposure",
	"ssr-hydration-xss",
	"remix-loader-exposure",
	// Per-response header / cookie hygiene: one finding per Set-Cookie response.
	"cookie-security-detect",

	// --- Informational recon & fingerprinting (Info/Low, fire once per response) ---

	// Tech-stack / framework fingerprints: "what stack is this host", repeated per URL.
	"wp-fingerprint",
	"flask-fingerprint",
	"rails-fingerprint",
	"aspnet-fingerprint",
	"django-fingerprint",
	"drupal-fingerprint",
	"joomla-fingerprint",
	"spring-fingerprint",
	"express-fingerprint",
	"fastapi-fingerprint",
	"graphql-fingerprint",
	"laravel-fingerprint",
	"symfony-fingerprint",
	"firebase-fingerprint",
	"dashboard-fingerprint",
	"java-server-fingerprint",
	"php-generic-fingerprint",
	"js-framework-fingerprint",
	"metaframework-fingerprint",
	"baas-endpoint-fingerprint",
	"grpc-web-detect",
	// Cloud / recon harvest & version disclosure: one fact per response.
	"subdomain-harvest",
	"cloud-storage-fingerprint",
	"cloud-storage-url-harvest",
	"cloud-storage-error-info",
	"software-version-header",
	"security-headers-missing",
	"permissions-policy-detect",
	// Endpoint / param observation: candidate lists, not vulns.
	"api-spec-detect",
	"api-version-detect",
	"endpoint-classifier",
	"idor-params-detect",
	"openredirect-params",
	"input-reflection-detect",
	"wasm-module-detect",
	"rails-action-cable-detect",
	"rails-active-storage-detect",
	// Rails health/info endpoint exposed (/up and friends): the same "Rails internals
	// reachable" fact reported once per matched path on a host.
	"rails-info-exposure",
	"password-autocomplete-detect",
	"sql-syntax-detect",
	// Per-response header / hygiene (Low): one finding per crawled page.
	"csp-weakness-audit",
	"cors-headers-detect",
	// Permissive CORS on one host, demonstrated via several probe techniques
	// (reflected / null / subdomain / prefix / suffix / port / scheme bypass) — each
	// fires as its own row with a distinct probe value, but they are all the same
	// broken-CORS issue on that asset. Collapse per host: same-URL technique variants
	// fold via the URL-dedup pass (each probe's request/response kept on the survivor
	// as AdditionalEvidence), and where the techniques span multiple URLs this
	// by-module entry unions their probe values onto the survivor.
	"cors-misconfiguration",
	"cors-vary-origin-missing",
	"mixed-content-detect",
	"content-type-mismatch",
	"express-session-audit",
	"aspnet-viewstate-detect",
	"subresource-integrity-detect",
	"wp-rest-api-detect",
	"drupal-api-detect",
	"joomla-api-detect",
	// Active, but fires once-per-asset informationally (escalates to High, which
	// keys separately): Next.js static chunk intel extraction.
	"nextjs-chunk-audit",

	// --- Active probe / behavior observations (Info candidates, one per probed URL) ---
	//
	// These send probes and record an Info-tier "this surface behaved like X" lead per
	// URL/param/payload. The differing URL/payload is the noise; the host-level fact —
	// "this host has cacheable path-confusion surface" / "template-ish reflection" /
	// "anomalous input behavior" — is what the operator triages, with the probed URLs
	// and payloads preserved on the survivor (MatchedAt + unioned extracted values). A
	// genuinely-confirmed finding from the same area escalates above Info and keys on
	// its own severity, so a real SSTI/cache vuln never merges into these Info leads.
	"cache-deception",
	"ssti-detection",
	"input-behavior-probe",
	"smart-behavior-detection",
}

// perRuleGroupModules are the modules grouped per (module, rule_name, severity,
// host) — see FindingGroupingConfig.ByRule. The lone member is secret-detect:
// its single module_id fronts every Kingfisher rule, so plain per-module grouping
// would wrongly merge unrelated secrets (an AWS key, a Slack token, a Looker
// client id) into one finding, while plain per-value grouping leaves a single
// noisy rule — e.g. "Looker Client ID" matching every content hash in a minified
// bundle's chunk-hash map — as dozens of near-identical findings. By-rule keying
// folds the latter to one finding (all matched values unioned on) while keeping
// the former apart.
var perRuleGroupModules = []string{
	"secret-detect",
}

// defaultFindingGrouping is the effective grouping config when none is set in
// YAML. Grouping is on by default with per-host scoping so a leaked secret seen
// across a site collapses to one finding without merging across hostnames, and
// the per-asset modules in perAssetGroupModules collapse to one finding per host
// instead of one per JS bundle / page.
func defaultFindingGrouping() FindingGroupingConfig {
	return FindingGroupingConfig{
		Enabled: true,
		PerHost: true,
		// Copy rather than share the package vars: this config is subject to YAML
		// profile overlays, and a slice-appending merge must not mutate the globals.
		ByModule: append([]string(nil), perAssetGroupModules...),
		ByRule:   append([]string(nil), perRuleGroupModules...),
		MaxURLs:  50,
	}
}

// ResolveGroupByValue returns the effective grouping config, falling back to the
// shipped default when unset (a nil pointer survives profile overlays via the
// omitempty tag, so this keeps grouping on for partial configs).
func (c *KnownIssueScanConfig) ResolveGroupByValue() FindingGroupingConfig {
	if c.GroupByValue != nil {
		return *c.GroupByValue
	}
	return defaultFindingGrouping()
}

// DefaultKnownIssueScanConfig returns default known-issue scan configuration.
//
// Severities defaults to critical+high only: at the default (balanced) intensity
// the known-issue scan focuses on high-signal findings rather than enumerating
// every info/low template, which keeps the phase within its time budget. Operators
// who want the full sweep can widen it with:
//
//	vigolium config set known_issue_scan.severities "critical,high,medium,low,info"
func DefaultKnownIssueScanConfig() *KnownIssueScanConfig {
	grouping := defaultFindingGrouping()
	return &KnownIssueScanConfig{
		Severities:  []string{"critical", "high"},
		ExcludeTags: []string{"dos"},
		// An exposed config.json is not uniformly critical — many ship only public
		// base URLs / feature flags. Record it as medium by default; operators can
		// raise it again or add their own remaps via known_issue_scan.severity_overrides.
		SeverityOverrides: map[string]string{
			"config-json-exposure-fuzz": "medium",
		},
		EnrichTargets: true,
		GroupByValue:  &grouping,
	}
}

// Validate checks known-issue scan configuration for errors.
func (c *KnownIssueScanConfig) Validate() error {
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true,
		"low": true, "info": true,
	}
	for _, s := range c.Severities {
		if !validSeverities[s] {
			return fmt.Errorf("known_issue_scan.severities: invalid severity %q", s)
		}
	}

	for tmpl, sev := range c.SeverityOverrides {
		if !validSeverities[strings.ToLower(strings.TrimSpace(sev))] {
			return fmt.Errorf("known_issue_scan.severity_overrides[%q]: invalid severity %q", tmpl, sev)
		}
	}

	if c.GroupByValue != nil && c.GroupByValue.MaxURLs < 0 {
		return fmt.Errorf("known_issue_scan.group_by_value.max_urls: must be >= 0, got %d", c.GroupByValue.MaxURLs)
	}

	return nil
}
