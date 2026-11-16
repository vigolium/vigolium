// Package waf provides WAF/CDN blocking detection implementation.
package waf

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// Rule defines detection logic for a specific WAF/CDN.
type Rule struct {
	// Name identifies the WAF/CDN (e.g., "cloudflare", "akamai").
	Name string

	// Priority determines check order (lower = checked first).
	Priority int

	// StatusCodes that may indicate blocking (empty = any status).
	StatusCodes []int

	// HeaderChecks are fast header-based detection checks.
	HeaderChecks []HeaderCheck

	// BodyChecks are slower body-based detection checks.
	BodyChecks []BodyCheck

	// Edges are the edge vendors (edgeBlockPages) whose own block page is a
	// strong signal for this rule once the vendor's presence headers identify
	// it in the path. The markers live in the shared table, not here.
	Edges []string
}

// HeaderCheck defines a header-based detection rule.
type HeaderCheck struct {
	// Header name to check (case-insensitive).
	Header string

	// Contains checks if header value contains this substring.
	Contains string

	// Equals checks if header value equals this exactly.
	Equals string

	// Pattern checks if header value matches this regex.
	Pattern *regexp.Regexp

	// Exists checks if header is present (value doesn't matter).
	Exists bool

	// Presence marks a header the edge stamps on every response it proxies
	// (Server: cloudflare, Cf-Ray, X-Amz-Cf-Id, X-Iinfo, …). It says the edge
	// is in the path, not that the edge answered, so on a status the
	// application also uses (403, 503, …) it corroborates like a weak body
	// check and never matches alone. On a status only an edge emits — 429 and
	// Cloudflare's 52x origin errors (edgeAuthoredStatus) — it is strong.
	Presence bool
}

// BodyCheck defines a body-based detection rule.
type BodyCheck struct {
	// Contains checks if body contains this substring.
	Contains string

	// Pattern checks if body matches this regex.
	Pattern *regexp.Regexp

	// Weak marks a generic phrase that also appears in ordinary (non-WAF)
	// application responses (e.g. Azure's bare "The request is blocked"). A weak
	// match alone never brands a response as this WAF: it only contributes once a
	// strong signal — a vendor-specific header or a non-weak body signal — also
	// matches. This keeps a plain application 403 from being misattributed to a
	// vendor and tripping the discovery block circuit breaker.
	Weak bool

	// containsLower is the lowercased byte form of Contains, precomputed once at
	// rule-build time (see normalizeBodyChecks) so matchBody compares against the
	// once-lowercased body without re-lowering/allocating the needle per call.
	containsLower []byte
}

// detector implements Detector interface.
// Uses a rule-based approach to detect WAF/CDN blocking responses.
type detector struct {
	rules []Rule
}

// NewDetector creates a new WAF detector with default rules.
func NewDetector() Detector {
	return &detector{
		rules: defaultRules(),
	}
}

// defaultDetector is a shared rule-based detector backing the package-level
// ClassifyParts helper. Rules are immutable after construction, so a single
// shared instance is safe for concurrent use.
var defaultDetector = &detector{rules: defaultRules()}

// ClassifyParts detects a WAF/CDN block from raw response primitives, returning
// nil when the response is not a block. It exists for callers (e.g. scan
// modules) that hold an httpmsg response — status, headers, body — rather than
// a responsechain.ResponseChain. The detection logic is identical to Detect.
func ClassifyParts(statusCode int, header http.Header, body []byte) *BlockResult {
	return defaultDetector.classify(statusCode, header, body)
}

// Detect analyzes an HTTP response for WAF/CDN blocking patterns.
// Returns nil if response is not detected as a WAF block.
func (d *detector) Detect(rc *responsechain.ResponseChain) *BlockResult {
	if rc == nil || !rc.Has() {
		return nil
	}

	resp := rc.Response()
	return d.classify(resp.StatusCode, resp.Header, rc.BodyBytes())
}

// classify runs the rule set against response primitives.
func (d *detector) classify(statusCode int, header http.Header, body []byte) *BlockResult {
	// Fast path: skip non-blocking status codes
	if !IsBlockStatusCode(statusCode) {
		return nil
	}

	// Lowercase the body once up front. Every rule's substring BodyChecks (7 for
	// Cloudflare alone, dozens across the rule set) need a case-insensitive
	// compare; lowercasing per-check re-copied the whole body 20-40 times for a
	// single blocking response — exactly when a WAF-protected target is already
	// hammering this path.
	var lowerBody []byte
	if len(body) > 0 {
		lowerBody = bytes.ToLower(body)
	}

	// Check each rule in priority order
	for _, rule := range d.rules {
		if result := d.matchRule(rule, header, body, lowerBody, statusCode); result != nil {
			return result
		}
	}

	return nil
}

// matchRule checks if a response matches a specific WAF rule.
func (d *detector) matchRule(rule Rule, header http.Header, body, lowerBody []byte, statusCode int) *BlockResult {
	// Check status code if rule has specific codes
	if len(rule.StatusCodes) > 0 && !containsInt(rule.StatusCodes, statusCode) {
		return nil
	}

	var indicators []string

	// A strong signal is a vendor-specific header or a non-weak body match — the
	// kind of signal that on its own reliably attributes a response to this WAF.
	strongMatched := false

	// Check headers first (faster). A Presence header on a status the
	// application also answers with only corroborates; every other header
	// match is strong.
	var weakIndicators []string
	for _, check := range rule.HeaderChecks {
		indicator := matchHeader(header, check)
		if indicator == "" {
			continue
		}
		if check.Presence && !edgeAuthoredStatus(statusCode) {
			weakIndicators = append(weakIndicators, indicator)
			continue
		}
		indicators = append(indicators, indicator)
		strongMatched = true
	}

	// Check body patterns. Weak body matches (generic phrases shared with plain
	// application responses) are held aside and only counted once a strong signal
	// corroborates them, so e.g. Azure's bare "The request is blocked" can't alone
	// brand an ordinary 403 as WAF traffic.
	for _, check := range rule.BodyChecks {
		indicator := matchBody(body, lowerBody, check)
		if indicator == "" {
			continue
		}
		if check.Weak {
			weakIndicators = append(weakIndicators, indicator)
		} else {
			indicators = append(indicators, indicator)
			strongMatched = true
		}
	}

	// The vendor's own block page (the shared edgeBlockPages table), attributed
	// by its presence headers, is strong.
	if len(rule.Edges) > 0 && len(body) > 0 {
		h := newEdgeHeaders(header.Get)
		for _, vendor := range rule.Edges {
			if edgeBlockPageOf(h, vendor, body) {
				indicators = append(indicators, "body: "+vendor+" block page")
				strongMatched = true
				break
			}
		}
	}

	// Rule matches only on a strong signal. Weak indicators ride along for
	// diagnostics once corroborated, but never trigger a match by themselves.
	if strongMatched {
		indicators = append(indicators, weakIndicators...)
		return &BlockResult{
			IsBlocked:  true,
			WAFType:    rule.Name,
			Indicators: indicators,
		}
	}

	return nil
}

// matchHeader checks if a header matches a HeaderCheck. It inspects every value
// of the header, not just the first: Set-Cookie in particular is delivered as one
// header line per cookie, so a fingerprinting cookie (e.g. datadome=, rbzid=,
// _pxhd) is frequently NOT the first Set-Cookie in the response — a Get()-style
// first-value check would miss it.
func matchHeader(headers http.Header, check HeaderCheck) string {
	values := headers.Values(check.Header)

	if check.Exists {
		if len(values) > 0 {
			return "header:" + check.Header
		}
		return ""
	}

	if len(values) == 0 {
		return ""
	}

	needle := strings.ToLower(check.Contains)
	for _, value := range values {
		if check.Equals != "" && strings.EqualFold(value, check.Equals) {
			return "header:" + check.Header + "=" + check.Equals
		}
		if check.Contains != "" && strings.Contains(strings.ToLower(value), needle) {
			return "header:" + check.Header + " contains " + check.Contains
		}
		if check.Pattern != nil && check.Pattern.MatchString(value) {
			return "header:" + check.Header + " matches pattern"
		}
	}

	return ""
}

// matchBody checks if body matches a BodyCheck. lowerBody is the caller's
// once-lowercased copy of body, reused across all checks for the case-insensitive
// Contains compare; the raw body is retained for case-sensitive pattern matching.
func matchBody(body, lowerBody []byte, check BodyCheck) string {
	if len(body) == 0 {
		return ""
	}

	if check.Contains != "" {
		needle := check.containsLower
		if needle == nil {
			// Rule wasn't run through normalizeBodyChecks (no production path does
			// this, but guard so an empty needle can't match every body).
			needle = []byte(strings.ToLower(check.Contains))
		}
		if bytes.Contains(lowerBody, needle) {
			return "body contains: " + truncate(check.Contains, 50)
		}
	}

	if check.Pattern != nil && check.Pattern.Match(body) {
		return "body matches pattern"
	}

	return ""
}

// IsBlockStatusCode reports whether code is one WAFs/CDNs commonly use for
// blocking responses. classify() uses it as its fast-path gate, and external
// callers use it as a cheap pre-gate before paying for the fuller header/body
// inspection in ClassifyParts (which reads the response body) — so a status that
// passes this gate is exactly one ClassifyParts may classify as a block.
func IsBlockStatusCode(code int) bool {
	switch code {
	case 403, 405, 406, 429, 501, 503:
		return true
	}
	// Cloudflare specific codes
	if code >= 520 && code <= 530 {
		return true
	}
	return false
}

// edgeAuthoredStatus reports whether code is one only an edge emits for itself
// — a throttle (429) or a Cloudflare origin-error page (520-530) — so the
// edge's presence header on it attributes the response to the edge.
func edgeAuthoredStatus(code int) bool {
	return code == 429 || (code >= 520 && code <= 530)
}

// containsInt checks if slice contains value.
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// truncate shortens a string for display.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// defaultRules returns the built-in WAF detection rules.
func defaultRules() []Rule {
	rules := []Rule{
		cloudflareRule(),
		akamaiRule(),
		awsWAFRule(),
		f5BigIPRule(),
		impervaRule(),
		sucuriRule(),
		modsecurityRule(),
		// Additional WAF / CDN vendors.
		azureRule(),
		fortiwebRule(),
		barracudaRule(),
		citrixNetscalerRule(),
		wallarmRule(),
		radwareRule(),
		reblazeRule(),
		wordfenceRule(),
		// Bot-management / anti-automation vendors. These gate scan traffic just
		// like a WAF (typically a 403 challenge/deny), so a hit is exactly the
		// "your traffic is being filtered" signal the block warning surfaces.
		datadomeRule(),
		perimeterxRule(),
		kasadaRule(),
		queueItRule(),
		genericRule(),
	}
	normalizeBodyChecks(rules)
	return rules
}

// normalizeBodyChecks precomputes the lowercased needle for every substring
// BodyCheck once, so the per-response classify loop never re-lowers/allocates it.
func normalizeBodyChecks(rules []Rule) {
	for i := range rules {
		for j := range rules[i].BodyChecks {
			bc := &rules[i].BodyChecks[j]
			if bc.Contains != "" {
				bc.containsLower = []byte(strings.ToLower(bc.Contains))
			}
		}
	}
}

func cloudflareRule() Rule {
	return Rule{
		Name:        "cloudflare",
		Priority:    1,
		StatusCodes: []int{403, 429, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "cloudflare", Presence: true},
			{Header: "Cf-Ray", Exists: true, Presence: true},
			{Header: "Cf-Mitigated", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Access denied | Cloudflare"},
			{Contains: "cf-error-code"},
			{Contains: "Just a moment..."},
			{Contains: "challenges.cloudflare.com"},
			{Contains: "_cf_chl_opt"},
			{Pattern: regexp.MustCompile(`(?i)error code:?\s*10[0-9]{2}`)}, // 1010, 1015, 1020, etc.
		},
		Edges: []string{"cloudflare"},
	}
}

func akamaiRule() Rule {
	return Rule{
		Name:        "akamai",
		Priority:    2,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "AkamaiGHost", Presence: true},
			{Header: "X-Akamai-Transformed", Exists: true, Presence: true},
			{Header: "Akamai-Origin-Hop", Exists: true, Presence: true},
		},
		BodyChecks: []BodyCheck{
			// Generic phrase: an application's own 403 says it too.
			{Contains: "Access Denied", Weak: true},
			{Contains: "Your access to this service has been temporarily limited"},
			{Contains: "ak_bmsc"},
			{Contains: "_abck"},
			{Pattern: regexp.MustCompile(`Reference\s*#?\s*[0-9]+\.[0-9a-f]+`)},
		},
		Edges: []string{"akamai"},
	}
}

func awsWAFRule() Rule {
	return Rule{
		Name:        "aws_waf",
		Priority:    3,
		StatusCodes: []int{403, 429, 405},
		HeaderChecks: []HeaderCheck{
			{Header: "X-Amzn-Waf-Action", Exists: true},
			{Header: "X-Amz-Cf-Id", Exists: true, Presence: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "awswaf"},
			{Contains: "AWS WAF"},
			{Contains: "Request blocked"},
			{Contains: "captcha.awswaf.com"},
			{Contains: "window.gokuProps"},
		},
		Edges: []string{"cloudfront", "awselb"},
	}
}

func f5BigIPRule() Rule {
	return Rule{
		Name:        "f5_bigip",
		Priority:    4,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "BIG-IP"},
			{Header: "Server", Contains: "BigIP"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "The requested URL was rejected"},
			{Contains: "support ID"},
			{Contains: "BIG-IP"},
			{Pattern: regexp.MustCompile(`support ID is:?\s*[0-9]+`)},
		},
	}
}

func impervaRule() Rule {
	return Rule{
		Name:        "imperva",
		Priority:    5,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "X-Iinfo", Exists: true, Presence: true},
			{Header: "X-CDN", Contains: "Incapsula", Presence: true},
			{Header: "X-CDN", Contains: "Imperva", Presence: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Request unsuccessful"},
			{Contains: "_Incapsula_"},
			{Contains: "visid_incap_"},
			{Contains: "Powered by Incapsula"},
			{Pattern: regexp.MustCompile(`Incapsula incident ID:\s*[0-9]+-[0-9]+`)},
		},
		Edges: []string{"imperva"},
	}
}

func sucuriRule() Rule {
	return Rule{
		Name:        "sucuri",
		Priority:    6,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "Sucuri"},
			{Header: "X-Sucuri-ID", Exists: true},
			{Header: "X-Sucuri-Cache", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Sucuri WebSite Firewall"},
			{Contains: "Access Denied - Sucuri Website Firewall"},
			{Contains: "sucuri.net/privacy-policy"},
			{Contains: "cloudproxy@sucuri.net"},
		},
	}
}

func modsecurityRule() Rule {
	return Rule{
		Name:        "modsecurity",
		Priority:    7,
		StatusCodes: []int{403, 406, 429, 501},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "ModSecurity"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Mod_Security"},
			{Contains: "ModSecurity"},
			{Contains: "NAXSI"},
			{Contains: "This error was generated by Mod_Security"},
			{Pattern: regexp.MustCompile(`(?i)not acceptable.*?security module`)},
		},
	}
}

func azureRule() Rule {
	return Rule{
		Name:        "azure",
		Priority:    8,
		StatusCodes: []int{403, 429, 503},
		HeaderChecks: []HeaderCheck{
			// Application Gateway WAF stamps its product name on the Server header;
			// Front Door WAF tags blocked requests with a trace ref.
			{Header: "Server", Contains: "Microsoft-Azure-Application-Gateway"},
			{Header: "X-Azure-Ref", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Microsoft-Azure-Application-Gateway"},
			// Generic phrase: Front Door/App Gateway emit it, but so do plain apps.
			// Only counts alongside a strong Azure signal (e.g. the X-Azure-Ref
			// header or the App Gateway product string above).
			{Contains: "The request is blocked", Weak: true},
		},
	}
}

func fortiwebRule() Rule {
	return Rule{
		Name:        "fortiweb",
		Priority:    9,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "FortiWeb"},
			{Header: "Set-Cookie", Contains: "FORTIWAFSID="},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Web Page Blocked"},
			{Contains: ".fgd_icon"},
			{Contains: "Web Filter Block Override"},
			{Contains: "fortinet"},
		},
	}
}

func barracudaRule() Rule {
	return Rule{
		Name:        "barracuda",
		Priority:    10,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			// Distinctive Barracuda load-balancer / WAF session cookies.
			{Header: "Set-Cookie", Contains: "barra_counter_session"},
			{Header: "Set-Cookie", Contains: "BNI__BARRACUDA"},
			{Header: "Set-Cookie", Contains: "BNI_persistence"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Barracuda"},
		},
	}
}

func citrixNetscalerRule() Rule {
	return Rule{
		Name:        "citrix_netscaler",
		Priority:    11,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			// NetScaler rewrites the Connection header into these misspelled forms —
			// a long-standing, pathognomonic fingerprint.
			{Header: "Cneonction", Exists: true},
			{Header: "nnCoection", Exists: true},
			{Header: "Via", Contains: "NS-CACHE"},
			{Header: "Set-Cookie", Contains: "NSC_"},
			{Header: "Set-Cookie", Contains: "ns_af="},
			{Header: "Set-Cookie", Contains: "citrix_ns_id"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "NS Transaction ID"},
		},
	}
}

func wallarmRule() Rule {
	return Rule{
		Name:        "wallarm",
		Priority:    12,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "nginx-wallarm"},
		},
	}
}

func radwareRule() Rule {
	return Rule{
		Name:        "radware",
		Priority:    13,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "X-SL-CompState", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Unauthorized Activity Has Been Detected"},
			{Contains: "Because your web request looks automated"},
			{Contains: "CloudWebSec.radware.com"},
		},
	}
}

func reblazeRule() Rule {
	return Rule{
		Name:        "reblaze",
		Priority:    14,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "Server", Contains: "Reblaze"},
			{Header: "Set-Cookie", Contains: "rbzid="},
			{Header: "Set-Cookie", Contains: "rbzsessionid"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "Current session has been terminated"},
			{Contains: "check.reblaze.com"},
		},
	}
}

func wordfenceRule() Rule {
	return Rule{
		Name:        "wordfence",
		Priority:    15,
		StatusCodes: []int{403, 429, 503},
		BodyChecks: []BodyCheck{
			{Contains: "Generated by Wordfence"},
			{Contains: "This response was generated by Wordfence"},
			{Contains: "Your access to this site has been limited"},
			{Contains: "wordfence.com"},
		},
	}
}

func datadomeRule() Rule {
	return Rule{
		Name:        "datadome",
		Priority:    16,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "X-DataDome", Exists: true},
			{Header: "X-DataDome-CID", Exists: true},
			{Header: "X-DataDomeResponse", Exists: true},
			{Header: "Set-Cookie", Contains: "datadome="},
		},
		BodyChecks: []BodyCheck{
			{Contains: "geo.captcha-delivery.com"},
			{Contains: "captcha-delivery.com"},
			{Contains: "datadome"},
		},
	}
}

func perimeterxRule() Rule {
	return Rule{
		Name:        "perimeterx",
		Priority:    17,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			// PerimeterX / HUMAN drops _px* sensor and cookie tokens.
			{Header: "Set-Cookie", Pattern: regexp.MustCompile(`(?i)_px[a-z0-9]*=`)},
		},
		BodyChecks: []BodyCheck{
			{Contains: "www.perimeterx.com"},
			{Contains: "perimeterx.com/whywasiblocked"},
			{Contains: "px-captcha"},
			{Contains: "Please verify you are a human"},
			{Contains: "Access to this page has been denied because we believe you are using automation tools"},
		},
	}
}

func kasadaRule() Rule {
	return Rule{
		Name:        "kasada",
		Priority:    18,
		StatusCodes: []int{403, 429},
		HeaderChecks: []HeaderCheck{
			{Header: "X-Kpsdk-Ct", Exists: true},
			{Header: "X-Kpsdk-Cd", Exists: true},
			{Header: "X-Kpsdk-A", Exists: true},
		},
		BodyChecks: []BodyCheck{
			{Contains: "kpsdk"},
		},
	}
}

func queueItRule() Rule {
	return Rule{
		Name:        "queue_it",
		Priority:    19,
		StatusCodes: []int{403, 429, 503},
		HeaderChecks: []HeaderCheck{
			{Header: "Set-Cookie", Contains: "QueueITAccepted"},
			{Header: "Set-Cookie", Contains: "Queue-it"},
		},
		BodyChecks: []BodyCheck{
			{Contains: "queue-it.net"},
			{Contains: "Queue-it"},
		},
	}
}

func genericRule() Rule {
	return Rule{
		Name:         "generic",
		Priority:     99, // Lowest priority - fallback
		StatusCodes:  []int{403, 429},
		HeaderChecks: []HeaderCheck{},
		BodyChecks: []BodyCheck{
			{Contains: "Access Denied"},
			{Contains: "Request Blocked"},
			{Contains: "You have been blocked"},
			{Contains: "Your IP has been blocked"},
			{Contains: "Rate limit exceeded"},
			{Contains: "Too many requests"},
			{Contains: "Forbidden"},
			{Contains: "blocked by"},
		},
	}
}
