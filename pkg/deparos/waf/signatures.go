package waf

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// Signatures is the one table of WAF/CDN block, challenge and presence
// signatures. Every classifier in the binary reads it: ClassifyResponse (the
// scan transports, discovery, the spider, deparos fingerprinting), EdgeFront
// (pre-arm pacing), infra's block detector and modkit's edge-block gate.
// `vigolium schema block-signatures -j` publishes it row for row, so a caller
// that classifies responses it fetched itself generates its table from this
// one instead of keeping a copy.
//
// Patterns, and why they are allowed here: each row is a vendor's own
// protocol header or a fixed string its generated block or challenge template
// emits. Matching one is deterministic validation of a response against a
// vendor-stamped shape, not a judgement about what the application is.
//
// Reading a row:
//
//   - kind is what a firing row says: challenge (a vendor interstitial),
//     block (a named vendor's block page or stamp), refused (a generic phrase
//     on a block status: nothing names an edge, and an application's own 403
//     reads the same) or presence (a header the edge stamps on every response
//     it proxies: it says the edge is in the path, never that it answered, so
//     a presence row never classifies a response alone).
//   - match.status is the status set the row applies on; a row whose match
//     names neither a header nor a body fires on the status alone.
//   - requires is any-of: at least one listed row must also match (on its own
//     status set). Presence rows are what most rows require.
//
// Rows are grouped by vendor; the first group (in table order) with a firing
// non-presence row is the response's classification. IDs are stable: a
// published id is never reused for a different signature.
//
// Reconciliation of the classifiers this table replaced (infra's
// ChallengeBodyMarkers and Cf-Mitigated check, deparos/waf's challenge and
// edge block-page tables and its per-vendor detector rules). Where they
// disagreed, the stricter reading wins:
//
//   - `_Incapsula_Resource` is Imperva's sensor script, on ordinary Imperva
//     pages too: never a challenge, and a block only on a block status beside
//     an Imperva presence header (imperva.block.incapsula-resource). The
//     detector's broader `_Incapsula_` needle is gone, and `visid_incap_`
//     needs the presence header as well.
//   - Cf-Mitigated counts only with its documented value `challenge`
//     (cloudflare.challenge.cf-mitigated), on a success or Cloudflare block
//     status. Any value still identifies Cloudflare in the path
//     (cloudflare.presence.cf-mitigated).
//   - `/cdn-cgi/challenge-platform/` is dropped: Cloudflare's JS-detection
//     injector loads from that path on ordinary pages. `_cf_chl_opt` counts as
//     `window._cf_chl_opt` on an HTML interstitial-sized body.
//   - Challenge body markers need an HTML (or untyped) body of at most
//     challengeMaxBody bytes, on any status they apply to.
//   - "Request unsuccessful" alone is a generic phrase: Imperva's block page
//     is recognised by its incident id.
//   - challenges.cloudflare.com is dropped (a page embedding a Turnstile
//     widget carries it) and "Just a moment..." needs a Cloudflare presence
//     header.
//   - Vendor block-page markers apply on the vendor's block statuses only.
//     CloudFront's 502/504 and the ELB's 503 origin-failure pages are the edge
//     reporting an unreachable origin, not a block, and are not here.
//   - Sucuri's and Azure Front Door's identifying headers are presence rows
//     like every other edge's: alone they classify only an edge-authored 429.
//   - F5 ASM's stock blocking page answers 200 OK: its full sentence counts
//     on a 200 HTML interstitial-sized body (f5_bigip.block.default-page);
//     the shorter phrases stay on block statuses.
//   - Weak, corroborate-only phrases (Akamai's "Access Denied", which an
//     application's 403 says too) are not rows: a weak phrase never changed a
//     verdict, only the diagnostics beside one.
var Signatures = append(slices.Clip(presenceRows), []Signature{
	// Cloudflare.
	challengeHeader("cloudflare", "cf-mitigated", union(challengeStatuses, cloudflareStatuses), "Cf-Mitigated", "challenge"),
	challengeBody("cloudflare", "chl-opt", union(challengeStatuses, cloudflareStatuses), "window._cf_chl_opt"),
	challengeBody("cloudflare", "noscript", union(challengeStatuses, cloudflareStatuses), "Enable JavaScript and cookies to continue"),
	{ID: "cloudflare.challenge.just-a-moment", Vendor: "cloudflare", Kind: KindSigChallenge,
		Match: Match{Status: cloudflareStatuses, BodyOp: OpIContains, Body: "Just a moment..."}, Requires: presenceOf("cloudflare")},
	block("cloudflare", "access-denied", cloudflareStatuses, body(OpIContains, "Access denied | Cloudflare")),
	block("cloudflare", "cf-error-code", cloudflareStatuses, body(OpIContains, "cf-error-code")),
	block("cloudflare", "error-1xxx", cloudflareStatuses, body(OpIRegex, `error code:?\s*10[0-9]{2}`)),
	edgePage("cloudflare", "cf-error-details", cloudflareStatuses, "cf-error-details", "cloudflare"),
	edgePage("cloudflare", "ray-id", cloudflareStatuses, "Cloudflare Ray ID", "cloudflare"),
	edgePage("cloudflare", "cf-wrapper", cloudflareStatuses, "cf-wrapper", "cloudflare"),
	edgePage("cloudflare", "attention-required", cloudflareStatuses, "Attention Required! | Cloudflare", "cloudflare"),
	edgePage("cloudflare", "sorry-blocked", cloudflareStatuses, "Sorry, you have been blocked", "cloudflare"),
	edgeStatus("cloudflare", union([]int{429}, cloudflareOriginErrors), "cloudflare"),

	// Akamai.
	challengeBody("akamai", "cp-challenge", union(challengeStatuses, akamaiStatuses), "/_sec/cp_challenge/"),
	block("akamai", "limited", akamaiStatuses, body(OpIContains, "Your access to this service has been temporarily limited")),
	block("akamai", "ak-bmsc", akamaiStatuses, body(OpIContains, "ak_bmsc")),
	block("akamai", "abck", akamaiStatuses, body(OpIContains, "_abck")),
	block("akamai", "reference-id", akamaiStatuses, body(OpRegex, `Reference\s*#?\s*[0-9]+\.[0-9a-f]+`)),
	edgePage("akamai", "edgesuite", akamaiStatuses, "errors.edgesuite.net", "akamai"),
	edgePage("akamai", "reference-entity", akamaiStatuses, "Reference&#32;&#35;", "akamai"),
	edgePage("akamai", "reference-hash", akamaiStatuses, "Reference #", "akamai"),
	edgeStatus("akamai", []int{429}, "akamai"),

	// AWS WAF, in front of CloudFront or an ELB/ALB. The CloudFront error page
	// and the ELB default 403 template are generic on their own (the latter is
	// nginx's stock 403), so they count beside the CloudFront or ELB header.
	challengeHeader("aws_waf", "waf-action", union(challengeStatuses, awsWAFStatuses), "X-Amzn-Waf-Action", "challenge", "captcha"),
	block("aws_waf", "waf-action", awsWAFStatuses, hdr("X-Amzn-Waf-Action", OpExists)),
	block("aws_waf", "awswaf", awsWAFStatuses, body(OpIContains, "awswaf")),
	block("aws_waf", "aws-waf", awsWAFStatuses, body(OpIContains, "AWS WAF")),
	block("aws_waf", "request-blocked", awsWAFStatuses, body(OpIContains, "Request blocked")),
	block("aws_waf", "goku-props", awsWAFStatuses, body(OpIContains, "window.gokuProps")),
	edgePage("aws_waf", "cloudfront-generated", awsWAFStatuses, "Generated by cloudfront", "cloudfront"),
	edgePage("aws_waf", "cloudfront-unsatisfied", awsWAFStatuses, "The request could not be satisfied", "cloudfront"),
	edgePage("aws_waf", "elb-403", awsWAFStatuses, "<center><h1>403 Forbidden</h1></center>", "awselb"),
	edgeStatus("aws_waf", []int{429}, "cloudfront"),

	// F5 BIG-IP ASM. Its default blocking response page answers 200 OK (the
	// policy's stock response headers are "HTTP/1.1 200 OK"), so the stock
	// page's full sentence counts on a 200 too, held to an HTML
	// interstitial-sized body like a challenge marker.
	block("f5_bigip", "server", blockStatuses, hdr("Server", OpContains, "BIG-IP", "BigIP")),
	{ID: "f5_bigip.block.default-page", Vendor: "f5_bigip", Kind: KindSigBlock,
		Match: Match{Status: []int{http.StatusOK}, BodyOp: OpContains, Body: "The requested URL was rejected. Please consult with your administrator.",
			BodyMaxBytes: challengeMaxBody, ContentType: "html"}},
	block("f5_bigip", "url-rejected", blockStatuses, body(OpIContains, "The requested URL was rejected")),
	block("f5_bigip", "support-id", blockStatuses, body(OpIContains, "support ID")),
	block("f5_bigip", "big-ip", blockStatuses, body(OpIContains, "BIG-IP")),

	// Imperva / Incapsula.
	challengeBody("imperva", "incident-id", challengeStatuses, "Incapsula incident ID"),
	block("imperva", "incident-id", blockStatuses, body(OpRegex, `Incapsula incident ID:\s*[0-9]+-[0-9]+`)),
	block("imperva", "powered-by", blockStatuses, body(OpIContains, "Powered by Incapsula")),
	edgePage("imperva", "incapsula-resource", blockStatuses, "_Incapsula_Resource", "imperva"),
	{ID: "imperva.block.visid-incap", Vendor: "imperva", Kind: KindSigBlock,
		Match: Match{Status: blockStatuses, BodyOp: OpIContains, Body: "visid_incap_"}, Requires: presenceOf("imperva")},
	edgeStatus("imperva", []int{429}, "imperva"),

	// Sucuri.
	challengeBody("sucuri", "cloudproxy-js", challengeStatuses, "sucuri_cloudproxy_js"),
	block("sucuri", "firewall", blockStatuses, body(OpIContains, "Sucuri WebSite Firewall")),
	block("sucuri", "privacy-policy", blockStatuses, body(OpIContains, "sucuri.net/privacy-policy")),
	block("sucuri", "cloudproxy-mail", blockStatuses, body(OpIContains, "cloudproxy@sucuri.net")),
	edgeStatus("sucuri", []int{429}, "sucuri"),

	// ModSecurity / NAXSI.
	block("modsecurity", "server", modsecStatuses, hdr("Server", OpContains, "ModSecurity")),
	block("modsecurity", "mod-security", modsecStatuses, body(OpIContains, "Mod_Security")),
	block("modsecurity", "modsecurity", modsecStatuses, body(OpIContains, "ModSecurity")),
	block("modsecurity", "naxsi", modsecStatuses, body(OpIContains, "NAXSI")),
	block("modsecurity", "not-acceptable", modsecStatuses, body(OpIRegex, `not acceptable.*?security module`)),

	// Azure Application Gateway and Front Door. "The request is blocked" is a
	// phrase plain applications say too; it counts beside Front Door's header.
	block("azure", "app-gateway-server", azureStatuses, hdr("Server", OpContains, "Microsoft-Azure-Application-Gateway")),
	block("azure", "app-gateway-body", azureStatuses, body(OpIContains, "Microsoft-Azure-Application-Gateway")),
	{ID: "azure.block.request-blocked", Vendor: "azure", Kind: KindSigBlock,
		Match: Match{Status: azureStatuses, BodyOp: OpIContains, Body: "The request is blocked"}, Requires: presenceOf("azure_frontdoor")},
	edgeStatus("azure", []int{429}, "azure_frontdoor"),

	// FortiWeb.
	block("fortiweb", "server", blockStatuses, hdr("Server", OpContains, "FortiWeb")),
	block("fortiweb", "cookie", blockStatuses, hdr("Set-Cookie", OpContains, "FORTIWAFSID=")),
	block("fortiweb", "page-blocked", blockStatuses, body(OpIContains, "Web Page Blocked")),
	block("fortiweb", "fgd-icon", blockStatuses, body(OpIContains, ".fgd_icon")),
	block("fortiweb", "block-override", blockStatuses, body(OpIContains, "Web Filter Block Override")),
	block("fortiweb", "fortinet", blockStatuses, body(OpIContains, "fortinet")),

	// Barracuda.
	block("barracuda", "cookie", blockStatuses, hdr("Set-Cookie", OpContains, "barra_counter_session", "BNI__BARRACUDA", "BNI_persistence")),
	block("barracuda", "barracuda", blockStatuses, body(OpIContains, "Barracuda")),

	// Citrix NetScaler: it rewrites the Connection header into these
	// misspelled forms, a long-standing fingerprint.
	block("citrix_netscaler", "cneonction", blockStatuses, hdr("Cneonction", OpExists)),
	block("citrix_netscaler", "nncoection", blockStatuses, hdr("nnCoection", OpExists)),
	block("citrix_netscaler", "via", blockStatuses, hdr("Via", OpContains, "NS-CACHE")),
	block("citrix_netscaler", "cookie", blockStatuses, hdr("Set-Cookie", OpContains, "NSC_", "ns_af=", "citrix_ns_id")),
	block("citrix_netscaler", "transaction-id", blockStatuses, body(OpIContains, "NS Transaction ID")),

	// Wallarm.
	block("wallarm", "server", blockStatuses, hdr("Server", OpContains, "nginx-wallarm")),

	// Radware.
	block("radware", "compstate", blockStatuses, hdr("X-SL-CompState", OpExists)),
	block("radware", "unauthorized-activity", blockStatuses, body(OpIContains, "Unauthorized Activity Has Been Detected")),
	block("radware", "looks-automated", blockStatuses, body(OpIContains, "Because your web request looks automated")),
	block("radware", "cloudwebsec", blockStatuses, body(OpIContains, "CloudWebSec.radware.com")),

	// Reblaze.
	block("reblaze", "server", blockStatuses, hdr("Server", OpContains, "Reblaze")),
	block("reblaze", "cookie", blockStatuses, hdr("Set-Cookie", OpContains, "rbzid=", "rbzsessionid")),
	block("reblaze", "session-terminated", blockStatuses, body(OpIContains, "Current session has been terminated")),
	block("reblaze", "check-reblaze", blockStatuses, body(OpIContains, "check.reblaze.com")),

	// Wordfence.
	block("wordfence", "generated-by", wordfenceStatuses, body(OpIContains, "Generated by Wordfence")),
	block("wordfence", "response-generated", wordfenceStatuses, body(OpIContains, "This response was generated by Wordfence")),
	block("wordfence", "access-limited", wordfenceStatuses, body(OpIContains, "Your access to this site has been limited")),
	block("wordfence", "wordfence-com", wordfenceStatuses, body(OpIContains, "wordfence.com")),

	// Bot-management and anti-automation vendors gate scan traffic like a WAF.
	// Their cookies ride healthy 200s too, so they classify only on a block
	// status.
	challengeBody("datadome", "captcha-delivery", challengeStatuses, "captcha-delivery.com"),
	block("datadome", "header", blockStatuses, hdr("X-DataDome", OpExists)),
	block("datadome", "cid-header", blockStatuses, hdr("X-DataDome-CID", OpExists)),
	block("datadome", "response-header", blockStatuses, hdr("X-DataDomeResponse", OpExists)),
	block("datadome", "cookie", blockStatuses, hdr("Set-Cookie", OpContains, "datadome=")),
	block("datadome", "captcha-delivery", blockStatuses, body(OpIContains, "captcha-delivery.com")),
	block("datadome", "datadome", blockStatuses, body(OpIContains, "datadome")),

	challengeBody("perimeterx", "px-captcha", challengeStatuses, `id="px-captcha"`),
	block("perimeterx", "cookie", blockStatuses, hdr("Set-Cookie", OpIRegex, `_px[a-z0-9]*=`)),
	block("perimeterx", "perimeterx-com", blockStatuses, body(OpIContains, "www.perimeterx.com")),
	block("perimeterx", "why-blocked", blockStatuses, body(OpIContains, "perimeterx.com/whywasiblocked")),
	block("perimeterx", "px-captcha", blockStatuses, body(OpIContains, "px-captcha")),
	block("perimeterx", "verify-human", blockStatuses, body(OpIContains, "Please verify you are a human")),
	block("perimeterx", "automation-tools", blockStatuses, body(OpIContains, "Access to this page has been denied because we believe you are using automation tools")),

	block("kasada", "ct-header", blockStatuses, hdr("X-Kpsdk-Ct", OpExists)),
	block("kasada", "cd-header", blockStatuses, hdr("X-Kpsdk-Cd", OpExists)),
	block("kasada", "a-header", blockStatuses, hdr("X-Kpsdk-A", OpExists)),
	block("kasada", "kpsdk", blockStatuses, body(OpIContains, "kpsdk")),

	block("queue_it", "cookie", queueItStatuses, hdr("Set-Cookie", OpContains, "QueueITAccepted", "Queue-it")),
	block("queue_it", "queue-it-net", queueItStatuses, body(OpIContains, "queue-it.net")),
	block("queue_it", "queue-it", queueItStatuses, body(OpIContains, "Queue-it")),

	// Vercel's and Netlify's bot-protection interstitials. Netlify's
	// proof-of-work page posts to its reserved /.netlify/ namespace; its inline
	// script emits the path JSON-escaped, so both forms are rows (the escaped
	// form is not a substring of the plain one). The bare "submit-challenge"
	// action name would misfire on a coding-challenge application.
	challengeHeader("vercel", "x-vercel-mitigated", challengeStatuses, "X-Vercel-Mitigated", "challenge"),
	challengeBody("netlify", "submit-challenge-escaped", union(challengeStatuses, blockStatuses), `\/.netlify\/submit-challenge`),
	challengeBody("netlify", "submit-challenge", union(challengeStatuses, blockStatuses), "/.netlify/submit-challenge"),

	// Generic phrases: a block status that names no vendor. Refused, never an
	// edge attribution.
	refused("access-denied", "Access Denied"),
	refused("request-blocked", "Request Blocked"),
	refused("you-have-been-blocked", "You have been blocked"),
	refused("ip-blocked", "Your IP has been blocked"),
	refused("rate-limit-exceeded", "Rate limit exceeded"),
	refused("too-many-requests", "Too many requests"),
	refused("forbidden", "Forbidden"),
	refused("blocked-by", "blocked by"),
}...)

// presenceRows are the table's presence rows: they identify the edge in the
// path and never classify alone. They open Signatures, and presenceOf reads
// them to build the other rows' requires lists.
var presenceRows = []Signature{
	presence("cloudflare", "server", hdr("Server", OpContains, "cloudflare")),
	presence("cloudflare", "cf-ray", hdr("Cf-Ray", OpExists)),
	presence("cloudflare", "cf-mitigated", hdr("Cf-Mitigated", OpExists)),
	presence("cloudfront", "x-amz-cf-id", hdr("X-Amz-Cf-Id", OpExists)),
	presence("cloudfront", "via", hdr("Via", OpContains, "cloudfront")),
	presence("cloudfront", "server", hdr("Server", OpEquals, "cloudfront")),
	presence("akamai", "server", hdr("Server", OpContains, "akamaighost")),
	presence("akamai", "x-akamai-transformed", hdr("X-Akamai-Transformed", OpExists)),
	presence("akamai", "origin-hop", hdr("Akamai-Origin-Hop", OpExists)),
	presence("imperva", "x-iinfo", hdr("X-Iinfo", OpExists)),
	presence("imperva", "x-cdn", hdr("X-Cdn", OpContains, "incapsula", "imperva")),
	presence("sucuri", "server", hdr("Server", OpContains, "sucuri")),
	presence("sucuri", "x-sucuri-id", hdr("X-Sucuri-Id", OpExists)),
	presence("sucuri", "x-sucuri-cache", hdr("X-Sucuri-Cache", OpExists)),
	presence("azure_frontdoor", "x-azure-ref", hdr("X-Azure-Ref", OpExists)),
	presence("awselb", "server", hdr("Server", OpPrefix, "awselb/")),
}

// Signature kinds (Signature.Kind).
const (
	KindSigChallenge = "challenge"
	KindSigBlock     = "block"
	KindSigRefused   = "refused"
	KindSigPresence  = "presence"
)

// Match operators. Header equals/contains/prefix compare case-insensitively
// against any of HeaderValues; body contains is byte-exact, icontains
// case-insensitive; regex and iregex are RE2 patterns (iregex
// case-insensitive) written without inline flags, so a caller in another
// language compiles them as written.
const (
	OpExists    = "exists"
	OpEquals    = "equals"
	OpContains  = "contains"
	OpIContains = "icontains"
	OpPrefix    = "prefix"
	OpRegex     = "regex"
	OpIRegex    = "iregex"
)

// challengeMaxBody bounds the body a challenge row reads: challenge pages are
// small interstitials, and a larger body is the application.
const challengeMaxBody = 64 << 10

// Signature is one row of Signatures and of `schema block-signatures -j`.
type Signature struct {
	// ID is stable: <vendor>.<kind>.<slug>.
	ID string `json:"id"`
	// Vendor is the edge or product a firing row names; "generic" for the
	// refused rows.
	Vendor string `json:"vendor"`
	// Kind is challenge, block, refused or presence.
	Kind  string `json:"kind"`
	Match Match  `json:"match"`
	// Requires lists row ids of which at least one must also match.
	Requires []string `json:"requires,omitempty"`
}

// Match is what a row tests. Every condition it names must hold.
type Match struct {
	// Status is the status set the row applies on; empty means any status
	// (presence rows only).
	Status []int `json:"status,omitempty"`
	// Header is a response header name; HeaderOp tests its values (every value
	// of a repeated header, Set-Cookie included).
	Header       string   `json:"header,omitempty"`
	HeaderOp     string   `json:"header_op,omitempty"`
	HeaderValues []string `json:"header_values,omitempty"`
	// Body is a needle or pattern; BodyOp says which.
	BodyOp string `json:"body_op,omitempty"`
	Body   string `json:"body,omitempty"`
	// BodyMaxBytes: a longer body never matches the row.
	BodyMaxBytes int `json:"body_max_bytes,omitempty"`
	// ContentType: a response that carries a Content-Type must contain this
	// substring (case-insensitive); an untyped response passes.
	ContentType string `json:"content_type,omitempty"`
}

// Status sets. blockStatuses is the vendor rules' default; the others are the
// vendors whose block templates ride further statuses.
var (
	challengeStatuses      = []int{http.StatusOK, http.StatusAccepted}
	blockStatuses          = []int{403, 429}
	cloudflareOriginErrors = []int{520, 521, 522, 523, 524, 525, 526, 527, 530}
	cloudflareStatuses     = union([]int{403, 429, 503}, cloudflareOriginErrors)
	akamaiStatuses         = blockStatuses
	awsWAFStatuses         = []int{403, 405, 429}
	modsecStatuses         = []int{403, 406, 429, 501}
	azureStatuses          = []int{403, 429, 503}
	wordfenceStatuses      = []int{403, 429, 503}
	queueItStatuses        = []int{403, 429, 503}
)

func hdr(name, op string, values ...string) Match {
	return Match{Header: name, HeaderOp: op, HeaderValues: values}
}

func body(op, needle string) Match { return Match{BodyOp: op, Body: needle} }

func presence(vendor, slug string, m Match) Signature {
	return Signature{ID: vendor + ".presence." + slug, Vendor: vendor, Kind: KindSigPresence, Match: m}
}

func block(vendor, slug string, status []int, m Match) Signature {
	m.Status = status
	return Signature{ID: vendor + ".block." + slug, Vendor: vendor, Kind: KindSigBlock, Match: m}
}

func challengeHeader(vendor, slug string, status []int, header string, values ...string) Signature {
	return Signature{ID: vendor + ".challenge." + slug, Vendor: vendor, Kind: KindSigChallenge,
		Match: Match{Status: status, Header: header, HeaderOp: OpEquals, HeaderValues: values}}
}

func challengeBody(vendor, slug string, status []int, marker string) Signature {
	return Signature{ID: vendor + ".challenge." + slug, Vendor: vendor, Kind: KindSigChallenge,
		Match: Match{Status: status, BodyOp: OpContains, Body: marker, BodyMaxBytes: challengeMaxBody, ContentType: "html"}}
}

// edgePage is a vendor block-page marker that counts only beside the edge's
// presence header: some are generic on their own, and the header attributes
// them.
func edgePage(vendor, slug string, status []int, marker, edge string) Signature {
	return Signature{ID: vendor + ".block." + slug, Vendor: vendor, Kind: KindSigBlock,
		Match: Match{Status: status, BodyOp: OpContains, Body: marker}, Requires: presenceOf(edge)}
}

// edgeStatus is a status only an edge emits for itself (a throttle, a
// Cloudflare origin-error page): there, the edge's presence header attributes
// the response to the edge.
func edgeStatus(vendor string, status []int, edge string) Signature {
	return Signature{ID: vendor + ".block.edge-status", Vendor: vendor, Kind: KindSigBlock,
		Match: Match{Status: status}, Requires: presenceOf(edge)}
}

func refused(slug, phrase string) Signature {
	return Signature{ID: "generic.refused." + slug, Vendor: "generic", Kind: KindSigRefused,
		Match: Match{Status: blockStatuses, BodyOp: OpIContains, Body: phrase}}
}

// presenceOf lists the presence row ids of edge, in table order.
func presenceOf(edge string) []string {
	var ids []string
	for _, r := range presenceRows {
		if r.Vendor == edge {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func union(sets ...[]int) []int {
	var out []int
	for _, s := range sets {
		for _, v := range s {
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
	}
	return out
}

// compiledSignature is a row with its patterns compiled and needles lowered.
type compiledSignature struct {
	Signature
	headerRe   *regexp.Regexp
	bodyRe     *regexp.Regexp
	bodyNeedle []byte
	lowerVals  []string
	requires   []int // indexes into compiled
}

// vendorGroup is one vendor's classifying rows, in table order.
type vendorGroup struct {
	vendor string
	rows   []int
}

var (
	compiled = mustCompileSignatures(Signatures)
	groups   = groupByVendor(compiled)
)

func mustCompileSignatures(rows []Signature) []compiledSignature {
	out, err := compileSignatures(rows)
	if err != nil {
		panic(err)
	}
	return out
}

// compileSignatures validates and compiles rows: unique ids, known kinds and
// operators, requires naming existing rows, and a condition on every row.
func compileSignatures(rows []Signature) ([]compiledSignature, error) {
	index := make(map[string]int, len(rows))
	for i, s := range rows {
		if _, dup := index[s.ID]; dup {
			return nil, fmt.Errorf("waf signature %q: duplicate id", s.ID)
		}
		index[s.ID] = i
	}
	out := make([]compiledSignature, len(rows))
	for i, s := range rows {
		c := compiledSignature{Signature: s}
		switch s.Kind {
		case KindSigChallenge, KindSigBlock, KindSigRefused, KindSigPresence:
		default:
			return nil, fmt.Errorf("waf signature %q: unknown kind %q", s.ID, s.Kind)
		}
		m := s.Match
		if m.Header == "" && m.BodyOp == "" && len(s.Requires) == 0 {
			return nil, fmt.Errorf("waf signature %q: matches nothing", s.ID)
		}
		if s.Kind == KindSigPresence && (len(m.Status) > 0 || len(s.Requires) > 0) {
			return nil, fmt.Errorf("waf signature %q: a presence row has no status or requires", s.ID)
		}
		if s.Kind != KindSigPresence && len(m.Status) == 0 {
			return nil, fmt.Errorf("waf signature %q: a classifying row names its statuses", s.ID)
		}
		if m.Header != "" {
			switch m.HeaderOp {
			case OpExists:
			case OpEquals, OpContains, OpPrefix:
				if len(m.HeaderValues) == 0 {
					return nil, fmt.Errorf("waf signature %q: %s needs header_values", s.ID, m.HeaderOp)
				}
				for _, v := range m.HeaderValues {
					c.lowerVals = append(c.lowerVals, strings.ToLower(v))
				}
			case OpRegex, OpIRegex:
				re, err := compilePattern(m.HeaderOp, firstOf(m.HeaderValues))
				if err != nil {
					return nil, fmt.Errorf("waf signature %q: %w", s.ID, err)
				}
				c.headerRe = re
			default:
				return nil, fmt.Errorf("waf signature %q: unknown header_op %q", s.ID, m.HeaderOp)
			}
		}
		switch m.BodyOp {
		case "":
		case OpContains:
			c.bodyNeedle = []byte(m.Body)
		case OpIContains:
			c.bodyNeedle = []byte(strings.ToLower(m.Body))
		case OpRegex, OpIRegex:
			re, err := compilePattern(m.BodyOp, m.Body)
			if err != nil {
				return nil, fmt.Errorf("waf signature %q: %w", s.ID, err)
			}
			c.bodyRe = re
		default:
			return nil, fmt.Errorf("waf signature %q: unknown body_op %q", s.ID, m.BodyOp)
		}
		if m.BodyOp != "" && m.Body == "" {
			return nil, fmt.Errorf("waf signature %q: empty body needle", s.ID)
		}
		for _, r := range s.Requires {
			j, ok := index[r]
			if !ok {
				return nil, fmt.Errorf("waf signature %q: requires unknown %q", s.ID, r)
			}
			c.requires = append(c.requires, j)
		}
		out[i] = c
	}
	return out, nil
}

func compilePattern(op, pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	if op == OpIRegex {
		pattern = "(?i)" + pattern
	}
	return regexp.Compile(pattern)
}

func firstOf(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func groupByVendor(rows []compiledSignature) []vendorGroup {
	var out []vendorGroup
	at := map[string]int{}
	for i, r := range rows {
		if r.Kind == KindSigPresence {
			continue
		}
		g, ok := at[r.Vendor]
		if !ok {
			g = len(out)
			at[r.Vendor] = g
			out = append(out, vendorGroup{vendor: r.Vendor})
		}
		out[g].rows = append(out[g].rows, i)
	}
	return out
}

// response is one classification's inputs, with the lowercased body computed
// on first need and each row's match memoised.
type response struct {
	status    int
	header    http.Header
	body      []byte
	lowerBody []byte
	ctype     string
	// memo holds row i's match: 0 not yet evaluated, 1 matched, -1 not.
	memo []int8
}

func newResponse(status int, header http.Header, body []byte) *response {
	return &response{status: status, header: header, body: body,
		ctype: strings.ToLower(header.Get("Content-Type")), memo: make([]int8, len(compiled))}
}

// matches reports whether row i's own conditions hold (requires aside).
func (r *response) matches(i int) bool {
	switch r.memo[i] {
	case 1:
		return true
	case -1:
		return false
	}
	v := r.match(&compiled[i])
	r.memo[i] = -1
	if v {
		r.memo[i] = 1
	}
	return v
}

func (r *response) match(c *compiledSignature) bool {
	m := c.Match
	if len(m.Status) > 0 && !slices.Contains(m.Status, r.status) {
		return false
	}
	if m.Header != "" && !r.headerMatches(c) {
		return false
	}
	if m.BodyOp != "" && !r.bodyMatches(c) {
		return false
	}
	return true
}

func (r *response) headerMatches(c *compiledSignature) bool {
	values := r.header.Values(c.Match.Header)
	if len(values) == 0 {
		return false
	}
	if c.Match.HeaderOp == OpExists {
		return true
	}
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch c.Match.HeaderOp {
		case OpRegex, OpIRegex:
			if c.headerRe.MatchString(raw) {
				return true
			}
		default:
			for _, want := range c.lowerVals {
				switch c.Match.HeaderOp {
				case OpEquals:
					if v == want {
						return true
					}
				case OpContains:
					if strings.Contains(v, want) {
						return true
					}
				case OpPrefix:
					if strings.HasPrefix(v, want) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (r *response) bodyMatches(c *compiledSignature) bool {
	m := c.Match
	if len(r.body) == 0 || (m.BodyMaxBytes > 0 && len(r.body) > m.BodyMaxBytes) {
		return false
	}
	if m.ContentType != "" && r.ctype != "" && !strings.Contains(r.ctype, m.ContentType) {
		return false
	}
	switch m.BodyOp {
	case OpContains:
		return bytes.Contains(r.body, c.bodyNeedle)
	case OpIContains:
		if r.lowerBody == nil {
			r.lowerBody = bytes.ToLower(r.body)
		}
		return bytes.Contains(r.lowerBody, c.bodyNeedle)
	default:
		return c.bodyRe.Match(r.body)
	}
}

// fires reports whether row i matches and, when it requires others, one of
// them matches too.
func (r *response) fires(i int) bool {
	if !r.matches(i) {
		return false
	}
	req := compiled[i].requires
	if len(req) == 0 {
		return true
	}
	for _, j := range req {
		if r.matches(j) {
			return true
		}
	}
	return false
}

// ClassifyResponse is the one block classifier: it runs Signatures against a
// response and returns the first vendor group (table order) with a firing
// classifying row, or nil. Indicators are the ids of every row of that group
// that fired; Challenge is set when one of them is a challenge row.
func ClassifyResponse(statusCode int, header http.Header, body []byte) *BlockResult {
	if !IsCandidateStatusCode(statusCode) {
		return nil
	}
	if header == nil {
		header = http.Header{}
	}
	r := newResponse(statusCode, header, body)
	for _, g := range groups {
		var fired []string
		challenge := false
		for _, i := range g.rows {
			if r.fires(i) {
				fired = append(fired, compiled[i].ID)
				challenge = challenge || compiled[i].Kind == KindSigChallenge
			}
		}
		if len(fired) > 0 {
			return &BlockResult{IsBlocked: true, WAFType: g.vendor, Indicators: fired, Challenge: challenge}
		}
	}
	return nil
}

// EdgeFront returns the slug of the CDN/WAF edge fronting a host, from the
// presence rows' headers, which ride on ordinary (non-block) responses such as
// a clean 200. "" when no known edge is fingerprinted.
//
// It answers a different question from ClassifyResponse — "is this host
// behind an edge that could arm a rate-based WAF once a scan bursts it?" — so
// the scanner can pace that host's active phase before it trips the edge,
// rather than only after the first block. The paced set is the major
// WAF-capable edges; a plain origin or a bare CDN passthrough is not paced.
func EdgeFront(header http.Header) string {
	if len(header) == 0 {
		return ""
	}
	r := newResponse(0, header, nil)
	for _, vendor := range edgeFrontVendors {
		for _, i := range presenceIndex[vendor] {
			if compiled[i].Match.Header != "" && r.matches(i) {
				return vendor
			}
		}
	}
	return ""
}

// edgeFrontVendors are the edges EdgeFront paces, in match order.
var edgeFrontVendors = []string{"cloudflare", "cloudfront", "akamai", "imperva", "sucuri", "azure_frontdoor"}

// presenceIndex maps a vendor to its presence rows' indexes.
var presenceIndex = func() map[string][]int {
	out := map[string][]int{}
	for i, c := range compiled {
		if c.Kind == KindSigPresence {
			out[c.Vendor] = append(out[c.Vendor], i)
		}
	}
	return out
}()
