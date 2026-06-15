// Package dashboardsig is a shared catalog of third-party dashboards, admin
// consoles, and self-hosted products (Grafana, Apache Airflow, GitLab, Jenkins,
// Kibana, Vault, Ollama, vLLM, ...) together with the signatures used to detect
// them two ways:
//
//   - Passively: recognise the product in an already-observed response
//     (passive/dashboard_fingerprint marks the product as detected tech + emits
//     an INFO finding).
//   - Actively: confirm the product by probing its health / version / config
//     endpoints (active/dashboard_exposure). When an endpoint leaks internals
//     without authentication (version, config, model list, cluster info) the
//     active prober escalates the finding to High.
//
// One catalog, two consumers: a new product is added once here and both the
// passive recogniser and the active prober pick it up automatically.
//
// Marker convention: every BodyMarker / Confirmer.Markers string MUST be
// lowercase. Bodies are lowercased once before matching, so mixed-case markers
// would silently never match. VersionRe / BodyRe regexps run against the
// ORIGINAL (non-lowercased) body and may use their own flags (e.g. (?i)).
package dashboardsig

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Product categories, used for tagging and reporting.
const (
	CatObservability = "observability"
	CatCICD          = "ci-cd"
	CatInfra         = "infra"
	CatData          = "data"
	CatAI            = "ai"
	CatAnalytics     = "analytics"
	CatOrchestration = "orchestration"
	CatCollab        = "collaboration"
	CatAutomation    = "automation"
	CatMessaging     = "messaging"
)

// HeaderSig matches a single response header. Name is matched case-insensitively.
// When Contains is set the header value (lowercased) must contain it; otherwise
// the mere presence of the header is the signal. These headers are deliberately
// product-unique (e.g. X-Jenkins, kbn-version, X-ClickHouse-Query-Id), so a
// single header hit is high-confidence.
type HeaderSig struct {
	Name     string
	Contains string // optional, lowercased substring requirement
}

// Confirmer is an endpoint probed during active scanning to confirm a product.
// A confirmer must assert at least one of: Markers, BodyRe, or HeaderName.
//
// When UnauthLeak is true, reaching the endpoint without authentication IS the
// finding (it discloses version / config / data), so the active prober escalates
// the severity to LeakSev. Otherwise the confirmer just establishes presence.
type Confirmer struct {
	Path string // path relative to the mount, e.g. "/api/health"

	Markers  [][]string // AND-of-OR groups matched against the (lowercased) body
	BodyRe   string     // optional: body must match this regexp (raw body)
	OKStatus []int      // acceptable status codes (default {200})

	// HeaderName/HeaderContains require a response header to confirm — useful for
	// endpoints whose body is empty or generic (MinIO health, ClickHouse query).
	HeaderName     string
	HeaderContains string // lowercased substring requirement on the header value

	Primary    bool              // probed at normal intensity (best low-FP endpoint)
	UnauthLeak bool              // reaching it unauth is itself the exposure
	LeakName   string            // short label, e.g. "version + database status"
	LeakSev    severity.Severity // severity when UnauthLeak fires (default High)
	VersionRe  string            // optional: capture group 1 = version (raw body)

	bodyRe    *regexp.Regexp
	versionRe *regexp.Regexp
}

// Product is one detectable dashboard / console / self-hosted application.
type Product struct {
	ID       string // stable slug, e.g. "grafana"
	Name     string // display name, e.g. "Grafana"
	Category string // one of the Cat* constants
	Tags     []string
	Ref      string // optional reference URL

	// Passive recognition (matched against an already-observed response).
	Headers       []HeaderSig // any-match (OR)
	Cookies       []string    // distinctive cookie names (lowercased, prefix match)
	BodyMarkers   [][]string  // AND-of-OR groups (lowercased)
	VersionRe     string      // optional: extract version from a passively-seen body
	VersionHeader string      // optional: a header whose value IS the version (e.g. X-Jenkins)

	// Active probing.
	Mounts     []string // extra mount prefixes tried at deep intensity (e.g. "/grafana")
	Confirmers []Confirmer

	// Login, when set, is a default-credential check the active prober runs after
	// the product is confirmed present (documented default pairs only; see
	// LoginProbe). nil for products with no known default-login template.
	Login *LoginProbe

	PresenceSev severity.Severity // severity for "recognised, no leak" (default Info)

	versionRe *regexp.Regexp
}

// Match is the result of recognising a product in a response.
type Match struct {
	Product    *Product
	Confidence severity.Confidence
	Signals    []string // human-readable evidence
	Version    string   // extracted version, or ""
}

func init() {
	for i := range Catalog {
		p := &Catalog[i]
		if p.VersionRe != "" {
			p.versionRe = regexp.MustCompile(p.VersionRe)
		}
		for j := range p.Confirmers {
			c := &p.Confirmers[j]
			if c.BodyRe != "" {
				c.bodyRe = regexp.MustCompile(c.BodyRe)
			}
			if c.VersionRe != "" {
				c.versionRe = regexp.MustCompile(c.VersionRe)
			}
		}
	}
}

// MatchPassive returns every product recognised in the observed response.
//
// A product matches when a unique header fires (→ Certain), or all of its body
// marker groups match (→ Firm), or a distinctive cookie is present together with
// the product name appearing in the body (→ Firm). Cookie-only or name-only
// signals are intentionally not enough.
func MatchPassive(obs Observed) []Match {
	bodyLower := strings.ToLower(obs.Body)
	// A page that declares itself a published article / blog post is writing
	// *about* a product, not serving its console — so a body-only marker match
	// (the product's name in the title or prose) is a false positive. A header
	// or cookie signal, which prose can't fake, still fingerprints it.
	article := looksLikeArticlePage(bodyLower)
	var out []Match
	for i := range Catalog {
		p := &Catalog[i]
		var sigs []string
		conf := severity.Confidence(0)

		headerHit := false
		var version string
		for _, h := range p.Headers {
			v, ok := obs.header(h.Name)
			if !ok {
				continue
			}
			if h.Contains != "" && !strings.Contains(strings.ToLower(v), h.Contains) {
				continue
			}
			headerHit = true
			conf = severity.Certain
			if v != "" {
				sigs = append(sigs, "Header: "+h.Name+": "+truncate(v, 80))
			} else {
				sigs = append(sigs, "Header: "+h.Name)
			}
		}

		bodyHit := false
		if len(p.BodyMarkers) > 0 {
			if matched, ok := matchAllGroups(bodyLower, p.BodyMarkers); ok {
				bodyHit = true
				if conf < severity.Firm {
					conf = severity.Firm
				}
				sigs = append(sigs, "Body: "+strings.Join(matched, ", "))
			}
		}

		cookieHit := false
		for _, cn := range p.Cookies {
			if obs.hasCookie(cn) {
				cookieHit = true
				sigs = append(sigs, "Cookie: "+cn)
			}
		}

		matched := headerHit || bodyHit
		if !matched && cookieHit && strings.Contains(bodyLower, strings.ToLower(p.Name)) {
			matched = true
			if conf < severity.Firm {
				conf = severity.Firm
			}
		}
		if !matched {
			continue
		}
		// Drop body-only matches on article/blog pages (see `article` above).
		if article && !headerHit && !cookieHit {
			continue
		}

		// Version: prefer an explicit version header, then a body regexp.
		if p.VersionHeader != "" {
			if v, ok := obs.header(p.VersionHeader); ok && v != "" {
				version = v
			}
		}
		if version == "" && p.versionRe != nil {
			version = firstSubmatch(p.versionRe, obs.Body)
		}

		out = append(out, Match{Product: p, Confidence: conf, Signals: sigs, Version: version})
	}
	return out
}

// Confirm evaluates a confirmer against a probe response. It returns the
// extracted version (may be ""), the number of independent patterns that matched
// (signals), and whether the response confirms the product.
//
// signals counts corroborating evidence so callers can demand multiple patterns
// before reporting (FP defense): each matched marker GROUP is one signal, a
// matched header is one, a matched BodyRe is one, and a successfully extracted
// version adds one. A confirmer that asserts nothing never confirms (signals 0).
//
// bodyLower must be strings.ToLower(body); callers pass it precomputed so the
// (potentially large) body is lowercased once per response rather than once per
// confirmer evaluated against it.
func (c *Confirmer) Confirm(status int, header func(name string) string, body, bodyLower string) (version string, signals int, ok bool) {
	if !c.statusOK(status) {
		return "", 0, false
	}
	if c.HeaderName != "" {
		v := header(c.HeaderName)
		if v == "" {
			return "", 0, false
		}
		if c.HeaderContains != "" && !strings.Contains(strings.ToLower(v), c.HeaderContains) {
			return "", 0, false
		}
		signals++
	}
	if len(c.Markers) > 0 {
		matched, m := matchAllGroups(bodyLower, c.Markers)
		if !m {
			return "", 0, false
		}
		signals += len(matched) // each AND-group is an independent pattern
	}
	if c.bodyRe != nil {
		if !c.bodyRe.MatchString(body) {
			return "", 0, false
		}
		signals++
	}
	if signals == 0 {
		return "", 0, false // a confirmer that asserts nothing never confirms
	}
	if c.versionRe != nil {
		if version = firstSubmatch(c.versionRe, body); version != "" {
			signals++
		}
	}
	return version, signals, true
}

// spaShellMarkers are client-side-framework / PWA fingerprints that identify a
// single-page-app HTML shell — a page that serves the same JS-bootstrapped
// document for every route. Mirrors the deparos SPA detection.
var spaShellMarkers = []string{
	`id="root"`, `id='root'`, "data-reactroot", "react-dom", "__react_devtools",
	"__next_data__", "/_next/static/", `id="__next"`,
	"ng-version", "<app-root", "angular.bootstrap",
	"__nuxt__", "/_nuxt/", `id="__nuxt"`, "__vue__",
	"__sveltekit", "/_app/immutable/",
	"/static/js/main.", "serviceworker.register", "navigator.serviceworker",
}

// LooksLikeSPAShell reports whether body is a single-page-app HTML shell. The
// active prober uses it to skip hosts that client-side-route every path to the
// same shell, where path probing almost never yields a real endpoint.
func LooksLikeSPAShell(body string) bool {
	if body == "" {
		return false
	}
	ls := strings.ToLower(body)
	if !strings.Contains(ls, "<html") && !strings.Contains(ls, "<!doctype html") && !strings.Contains(ls, "<div") {
		return false // not an HTML document
	}
	for _, m := range spaShellMarkers {
		if strings.Contains(ls, m) {
			return true
		}
	}
	return false
}

// articleLDMarkers are schema.org JSON-LD @type values a blog/CMS emits for a
// published article. A product dashboard never serves these.
var articleLDMarkers = []string{
	`"@type":"article"`, `"@type": "article"`,
	`"@type":"blogposting"`, `"@type": "blogposting"`,
	`"@type":"newsarticle"`, `"@type": "newsarticle"`,
	`"@type":"techarticle"`, `"@type": "techarticle"`,
}

// looksLikeArticlePage reports whether bodyLower (already lowercased) is a
// published article / blog post rather than a product UI. It keys on the
// OpenGraph og:type=article meta and schema.org Article/BlogPosting JSON-LD —
// markup blogs and CMSes emit but product consoles never do. Used to suppress
// body-only dashboard fingerprints on pages that merely write about a product.
func looksLikeArticlePage(bodyLower string) bool {
	// OpenGraph: <meta property="og:type" content="article"> — attribute order
	// and quoting vary, so check for an "article" value near the og:type token.
	if i := strings.Index(bodyLower, "og:type"); i >= 0 {
		lo := i - 64
		if lo < 0 {
			lo = 0
		}
		hi := i + 80
		if hi > len(bodyLower) {
			hi = len(bodyLower)
		}
		win := bodyLower[lo:hi]
		if strings.Contains(win, `"article"`) || strings.Contains(win, `'article'`) {
			return true
		}
	}
	for _, m := range articleLDMarkers {
		if strings.Contains(bodyLower, m) {
			return true
		}
	}
	return false
}

// Severity returns the severity to report for a confirmer hit.
func (c *Confirmer) Severity() severity.Severity {
	if c.UnauthLeak {
		if c.LeakSev != 0 {
			return c.LeakSev
		}
		return severity.High
	}
	return 0 // caller falls back to the product's presence severity
}

func (c *Confirmer) statusOK(status int) bool {
	if len(c.OKStatus) == 0 {
		return status == 200
	}
	for _, s := range c.OKStatus {
		if s == status {
			return true
		}
	}
	return false
}

// PresenceSeverity returns the product's "recognised, no leak" severity,
// defaulting to Info.
func (p *Product) PresenceSeverity() severity.Severity {
	if p.PresenceSev != 0 {
		return p.PresenceSev
	}
	return severity.Info
}

// matchAllGroups reports whether hayLower (already lowercased) contains at least
// one needle from EACH group. Returns the first needle matched per group.
func matchAllGroups(hayLower string, groups [][]string) (matched []string, ok bool) {
	for _, g := range groups {
		hit := ""
		for _, needle := range g {
			if needle != "" && strings.Contains(hayLower, needle) {
				hit = needle
				break
			}
		}
		if hit == "" {
			return nil, false
		}
		matched = append(matched, hit)
	}
	return matched, true
}

// firstSubmatch returns capture group 1 of the first match (catalog version
// patterns always carry one), or "" if there is no match.
func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// References returns the product's reference URL as a slice (nil when unset),
// shaped for output.Info.Reference.
func (p *Product) References() []string {
	if p.Ref == "" {
		return nil
	}
	return []string{p.Ref}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
