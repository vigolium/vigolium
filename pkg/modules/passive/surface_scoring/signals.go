package surface_scoring

import (
	"math/bits"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/infra/dashboardsig"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// Signal is one bit of attack-surface evidence. The score is the popcount of the
// set bits scaled onto 0-100, so every signal is worth the same and the score is
// reproducible from the record alone.
type Signal uint32

const (
	// -- Input surface: can an active module act on this record at all? --

	// SignalHasInput - the OBSERVED request carried client-supplied input: a query
	// string or a body. Attacker-actionable immediately, which is what makes it
	// the strongest single predictor in the set.
	SignalHasInput Signal = 1 << iota
	// SignalAdvertisedInput - the response reveals input surface the observed
	// request did not exercise: an Allow / Access-Control-Allow-Methods listing a
	// mutating method, or form markup in the body.
	//
	// Its own bit rather than folded into SignalHasInput. A probe sends one bare
	// GET per host, so without this the input axis would be dead on exactly the
	// corpus that most needs ranking - but "<form> somewhere on the page" is true
	// of most HTML documents, and merging the two would have made the strong
	// predictor near-constant on an HTML corpus. That is the same defect the
	// SignalAuthBearing and SignalDynamic comments below describe avoiding.
	SignalAdvertisedInput
	// SignalStateChanging - a method that mutates (POST/PUT/PATCH/DELETE).
	// Drives access-control, CSRF and mass-assignment surface.
	SignalStateChanging
	// SignalUpload - the request is a file upload (multipart) or the response
	// offers one (a file input). Its own vulnerability class.
	SignalUpload

	// -- Context: does the stack or auth posture raise the odds? --

	// SignalTechStack - the host has at least one detected technology stack.
	// Host-scoped, so it is resolved at flush rather than per record (see Module).
	SignalTechStack
	// SignalLegacyStack - the path ends in a server-executed extension of an
	// older generation (.php, .jsp, .do, .aspx, .cgi...). These map a file
	// directly to a handler, predate framework-level defaults, and are what the
	// Struts/PHP/ASP.NET module families exist for.
	SignalLegacyStack
	// SignalAuthBearing - the exchange carries identity: an Authorization header,
	// or a session cookie in either direction.
	//
	// Deliberately NOT "any cookie". A CDN sets __cf_bm and an analytics tag sets
	// _ga on essentially every response they front, so crediting any Set-Cookie
	// made this bit near-constant on a CDN-fronted corpus - a constant added to
	// every score, which changes no ordering and costs a signal slot.
	SignalAuthBearing
	// SignalAuthSurface - the exchange advertises an authentication boundary: a
	// WWW-Authenticate challenge, a password input, or a redirect into an SSO /
	// OAuth / SAML flow.
	//
	// Distinct from SignalAuthBearing, which is about a session already in hand.
	// A host with accounts is a host with access-control surface, and on a sweep
	// a login page is the single most informative thing a bare GET can return.
	SignalAuthSurface
	// SignalNonStandardPort - the endpoint answers on a port other than 80/443.
	// On a host list this is disproportionately a dev, admin, or internal service
	// that was never meant to be reachable.
	SignalNonStandardPort

	// -- Shape: what does the response look like? --

	// SignalRichHTML - an HTML document carrying interactive or navigational
	// substance (form inputs, or a real set of links).
	SignalRichHTML
	// SignalSPA - the response is a single-page-app shell.
	SignalSPA
	// SignalJSON - the response body is JSON.
	SignalJSON
	// SignalResponsive - the application answered: not a WAF/CDN edge block, and
	// either a success status or an error verbose enough to leak a stack trace.
	SignalResponsive

	// -- Posture: what do the headers say about the origin behind the edge? --

	// SignalDynamic - the response is origin-rendered or personalized rather than
	// served from an edge cache: an explicit no-store/private/no-cache, or a Vary
	// on Cookie/Authorization, and not a cache hit.
	//
	// Positive evidence only. "No cache headers at all" is the majority case and
	// crediting it would make the bit another near-constant; what earns the point
	// is the origin explicitly saying this response is per-request.
	SignalDynamic
	// SignalPermissiveCORS - the response opts into cross-origin reads: an
	// Access-Control-Allow-Origin of "*" or "null", or any allowed origin
	// combined with Access-Control-Allow-Credentials. A specific allowlisted
	// origin without credentials is normal configuration and earns nothing.
	SignalPermissiveCORS
	// SignalLeakedInternals - the response exposes something about the origin it
	// did not mean to: a source map reference, a directory listing, an
	// origin/dev-server banner, or a debug/version header.
	SignalLeakedInternals
	// SignalAPISurface - the endpoint presents as a programmatic API beyond
	// merely returning JSON: rate-limit or gateway headers, an API/GraphQL path,
	// or an OpenAPI/Swagger/GraphiQL document.
	SignalAPISurface

	// signalSentinel must stay LAST: it is the bit after the final signal, which
	// is what lets allSignalBits and signalCount derive themselves.
	signalSentinel
)

// allSignalBits has every defined signal bit set.
const allSignalBits = Signal(signalSentinel - 1)

// signalCount is how many signals the set defines, derived from the const block
// so that adding a signal cannot leave the scale behind. It used to be a
// hand-written 16 that a test compared against a hand-written slice, which is
// two places to update and one of them silently wrong if forgotten.
var signalCount = bits.OnesCount32(uint32(allSignalBits))

// maxScore is the top of the stored scale, matching the 0-100 range documented
// on database.HTTPRecord.SurfaceScore and assumed by every consumer threshold
// (--min-surface, the REST filter, `traffic --sort surface_score`).
const maxScore = 100

// richHTMLMinAnchors is how many <a > tags an HTML document needs to count as
// navigationally rich when it carries no form inputs. A single "back to home"
// link is not surface; a nav bar is.
const richHTMLMinAnchors = 5

// apiDocPrefixBytes bounds the raw-body scan for OpenAPI/Swagger markers on JSON
// responses. A spec document names itself in its first object key, so a prefix
// is enough - and the JSON path deliberately never takes a full lowercase copy
// of the body, which for a large API response is the most expensive thing this
// module could do.
const apiDocPrefixBytes = 2048

// legacyHandlerExtensions are path extensions that name a server-executed
// handler from an older application generation. Deliberately NOT included:
// .js/.ts (client-side), .html/.htm (static), and .json/.xml (data), none of
// which imply a server-side execution model. Mirrors the shape of
// modkit.HasStaticAssetExtension.
var legacyHandlerExtensions = []string{
	".php", ".php3", ".php4", ".php5", ".php7", ".phtm", ".phtml", ".phps",
	".asp", ".aspx", ".asmx", ".ashx", ".axd",
	".jsp", ".jspx", ".jspa", ".jsf", ".do", ".action",
	".cfm", ".cfml",
	".cgi", ".pl", ".shtml",
}

// legacyHandlerPathInfoPrefixes is legacyHandlerExtensions with a trailing
// slash, for the PATH_INFO form (/index.php/users/1). Built once: concatenating
// inside the match loop cost 24 throwaway allocations on every record scanned.
var legacyHandlerPathInfoPrefixes = func() []string {
	out := make([]string, len(legacyHandlerExtensions))
	for i, ext := range legacyHandlerExtensions {
		out[i] = ext + "/"
	}
	return out
}()

// mutatingMethods are the methods that, when advertised by a response, mean the
// endpoint accepts input the observed request did not send.
var mutatingMethods = []string{"post", "put", "patch", "delete"}

// originServerBanners are Server values that name an application server or
// development server directly, meaning the response came from an origin rather
// than from a CDN or hardened reverse proxy. Matched as lowercase substrings;
// "thin/" and "php-cli" carry their separator so they cannot match inside an
// unrelated word.
var originServerBanners = []string{
	"werkzeug", "gunicorn", "jetty", "webrick", "puma", "thin/", "tornado",
	"kestrel", "hypercorn", "uvicorn", "waitress", "sinatra", "rack",
	"mongrel", "jboss", "glassfish", "weblogic", "development server",
	"simplehttp", "php-cli",
}

// debugHeaders leak a framework version or an internal identifier by their mere
// presence. Kept tight on purpose: X-Powered-By is common enough on PHP and
// Express corpora to behave like a constant, so it is not here.
var debugHeaders = []string{
	"X-Debug-Token", "X-Debug-Token-Link", "X-AspNet-Version",
	"X-AspNetMvc-Version", "X-Backend-Server", "X-Symfony-Profiler",
}

// apiHeaderPrefixes are response-header name prefixes that mark a programmatic
// API: client-visible rate limiting, or an API gateway announcing itself.
var apiHeaderPrefixes = []string{
	"x-ratelimit-", "ratelimit-", "x-rate-limit-",
	"x-api-version", "x-kong-", "x-envoy-upstream-", "x-amzn-requestid",
}

// apiPathMarkers are lowercase request-path substrings that name an API route.
// Version segments (/v1/, /v2/) are deliberately absent: they appear in docs and
// asset paths often enough to be noise.
var apiPathMarkers = []string{"/api/", "/graphql", "/odata", "/jsonrpc", "/rest/"}

// apiDocMarkers name an interface description document or explorer UI.
var apiDocMarkers = []string{`"openapi"`, `"swagger"`, "swagger-ui", "graphiql", "redoc"}

// dirListingHints are the cheap pre-gate for a directory listing: enough to
// decide whether modkit.DetectDirectoryListingServer's fuller (and pricier)
// analysis is worth running on this body.
var dirListingHints = []string{"index of ", "directory listing for ", "<title>directory:"}

// cacheHitHeaders carry an explicit cache hit/miss status. Mirrors the names
// infra.CacheState treats as hit indicators, so the two agree about what a hit
// is; see isCacheHitHeader for why this module answers the question itself.
var cacheHitHeaders = []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status"}

// passwordInputMarkers are the three ways a password field is written in the
// wild, mirroring hasFileInput's quoting variants.
var passwordInputMarkers = []string{
	`type="password"`, "type='password'", "type=password",
}

// Score converts a signal bitmask to the stored surface score.
//
// The scale is "percent of signal classes present" rather than a flat points-per
// -signal: at 16 signals no whole number of points divides 100, and a 10-point
// scheme clamped at the ceiling would score every record with ten or more
// signals as 100, flattening exactly the top band that ranking exists to
// separate. Truncating division keeps the mapping monotonic - more signals is
// never a lower score - and a full house scores exactly maxScore.
func (s Signal) Score() int {
	return bits.OnesCount32(uint32(s)) * maxScore / signalCount
}

// recordSignals computes the signals derivable from the record itself. The
// host-scoped SignalTechStack is deliberately NOT computed here: under
// ParallelPassive every eligible passive module for one record runs
// concurrently, so reading the tech registry at this point races the very
// fingerprint module that would populate it. Returns 0 when there is no
// response, which cannot earn any signal.
func recordSignals(item *httpmsg.HttpRequestResponse, host string, scanCtx *modkit.ScanContext) Signal {
	return RecordSignals(item, func() modkit.ContentClass {
		if scanCtx == nil {
			return modkit.ContentClassUnknown
		}
		return scanCtx.ContentClass.Get(host)
	})
}

// IngestScore is the record-scoped surface score computed at ingest, before
// any module ran: the record writer stamps it so a fresh scan's
// assessment order (risk_score DESC, surface_score DESC) is not merely
// chronological. The passive module re-scores at flush with the host-scoped
// tech signal added, which can only raise it.
func IngestScore(item *httpmsg.HttpRequestResponse) int {
	return RecordSignals(item, nil).Score()
}

// RecordSignals is the pure record-scoped signal computation. hostClass, when
// non-nil, resolves the host's content class for a record whose own
// Content-Type is indeterminate.
func RecordSignals(item *httpmsg.HttpRequestResponse, hostClass func() modkit.ContentClass) Signal {
	if item == nil {
		return 0
	}
	req := item.Request()
	resp := item.Response()
	if req == nil || resp == nil {
		return 0
	}

	var out Signal

	// -- request-derived (cheap, no body work) --

	// Path() includes any query string and is used by two predicates; lowered
	// once here rather than inside each. Go's ToLower returns the input unchanged
	// for an all-lowercase ASCII string, so the common case still costs nothing.
	lowerPath := strings.ToLower(req.Path())

	if hasClientInput(req) {
		out |= SignalHasInput
	}
	if isStateChanging(req.Method()) {
		out |= SignalStateChanging
	}
	if hasLegacyHandlerExtension(lowerPath) {
		out |= SignalLegacyStack
	}
	if isMultipartRequest(req) {
		out |= SignalUpload
	}
	if isNonStandardPort(req) {
		out |= SignalNonStandardPort
	}

	// -- response headers (cheap, still no body work) --
	//
	// Every predicate here reads only the head, so they run before the
	// content-class branch and apply equally to a JSON API, an HTML page and a
	// binary download.
	//
	// Headers() itself is memoized and free; what costs is walking it. scanHeaders
	// answers the three whole-slice questions (API markers, debug/internal
	// headers, cache layer) in ONE pass, because each was independently walking
	// every header and lowercasing every name - 54 of the 55 allocations this
	// block used to make. Everything below it reads a single named header.
	headers := resp.Headers()
	hdr := scanHeaders(headers)

	if isResponsive(resp) {
		out |= SignalResponsive
	}
	if advertisesMutatingMethod(resp) {
		out |= SignalAdvertisedInput
	}
	if isDynamicOrigin(resp, hdr) {
		out |= SignalDynamic
	}
	if hasPermissiveCORS(resp) {
		out |= SignalPermissiveCORS
	}
	if hdr.debugHeader || serverBannerLeaks(resp) {
		out |= SignalLeakedInternals
	}
	if hdr.apiHeader || hasAPIPath(lowerPath) {
		out |= SignalAPISurface
	}
	if isAuthBearing(req, headers) {
		out |= SignalAuthBearing
	}
	if headersAdvertiseAuth(resp) {
		out |= SignalAuthSurface
	}

	class := modkit.ResponseContentClass(item)
	if class == modkit.ContentClassUnknown {
		// The record's own Content-Type is indeterminate - fall back to the host's
		// root class, the same two-tier resolution the executor's content-class
		// gate uses (see Executor.passesContentClassFilter). Resolved here rather
		// than by the caller because it is an LRU lookup under a lock and this
		// branch is the minority: most records carry a usable Content-Type.
		if hostClass != nil {
			class = hostClass()
		}
	}

	if class == modkit.ContentClassJSON {
		out |= SignalJSON
		// A spec document is JSON that describes an API, which is more than the
		// JSON bit already says. Scanned over a bounded raw prefix so the JSON
		// path keeps its promise of never taking a full lowercase body copy.
		if out&SignalAPISurface == 0 && bodyPrefixHasAPIDoc(resp) {
			out |= SignalAPISurface
		}
		return out
	}

	// Every remaining signal reads markup, so a confirmed binary body can skip
	// the body work entirely - including BodyLowerString, whose lowered copy is a
	// second full-body allocation that nothing else would have asked for on an
	// image, font or PDF record.
	if class == modkit.ContentClassBinary {
		return out
	}

	// BodyLowerString is memoized on the response, so the body predicates below
	// share one lowercase copy rather than each making their own.
	lowerBody := resp.BodyLowerString()

	if class == modkit.ContentClassHTML && isRichHTML(lowerBody) {
		out |= SignalRichHTML
	}
	if dashboardsig.LooksLikeSPAShellLower(lowerBody) {
		out |= SignalSPA
	}

	// The remaining body signals share one shape: skip the scan if the bit is
	// already set, otherwise pay for a full-body pass. A table rather than five
	// hand-written stanzas so the guarded bit and the assigned bit cannot drift
	// apart - they were two separate mentions of the same constant, five times.
	//
	// The guards are load-bearing, not cosmetic: setting an already-set bit is a
	// no-op, but skipping the scan is the point. Ordered cheapest-first.
	for _, c := range bodySignals {
		if out&c.bit == 0 && c.match(lowerBody) {
			out |= c.bit
		}
	}
	// Directory listings need the response, not just the lowered body, so they
	// sit outside the table.
	if out&SignalLeakedInternals == 0 && bodyLeaksInternals(resp, lowerBody) {
		out |= SignalLeakedInternals
	}

	return out
}

// bodySignals pairs each body-derived signal with the predicate that sets it.
var bodySignals = []struct {
	bit   Signal
	match func(lowerBody string) bool
}{
	{SignalAdvertisedInput, hasFormMarkup},
	{SignalUpload, hasFileInput},
	{SignalAuthSurface, hasPasswordInput},
	{SignalAPISurface, func(b string) bool { return containsAny(b, apiDocMarkers) }},
}

// containsAny reports whether haystack contains any of the needles. The needles
// are lowercase literals and haystack must already be lowercased.
func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// hasClientInput reports whether the request carries anything an active module
// could inject into.
//
// Two families of position are deliberately not counted, both for the same
// reason - a signal that is true for nearly every record adds a constant and
// changes no ordering, which is the defect that makes a host-wide tech tag
// useless for ranking within a host:
//
//   - headers and cookies: every request has headers;
//   - path folder / path filename: an insertion-point analysis synthesizes these
//     from the path itself, so any URL with a segment has them. Counting them
//     made this signal fire on 100% of records in the module's own tests.
//
// What remains - a query string, or a body - is answerable from the request
// directly. It deliberately does NOT go through ScanContext.GetInsertionPoints:
// that cache keys shallow analyses separately from the nested ones every active
// module asks for, so this module would never hit a warm entry, would pay a full
// CreateAllInsertionPoints (including a raw-request clone) per record, and would
// insert 290k shallow entries that evict the nested ones the active fleet reuses.
func hasClientInput(req *httpmsg.HttpRequest) bool {
	if len(req.Body()) > 0 {
		return true
	}
	u, err := req.URL()
	return err == nil && u != nil && u.RawQuery != ""
}

// advertisesMutatingMethod reports whether the response says the endpoint
// accepts a method that carries a body, even though the observed request did
// not use one. Allow answers it for a plain endpoint; CORS preflight metadata
// answers it for an API that publishes its own method list.
func advertisesMutatingMethod(resp *httpmsg.HttpResponse) bool {
	allow := resp.Header("Allow")
	if cors := resp.Header("Access-Control-Allow-Methods"); cors != "" {
		allow += "," + cors
	}
	if allow == "" {
		return false
	}
	allow = strings.ToLower(allow)
	return containsAny(allow, mutatingMethods)
}

// hasFormMarkup reports whether the body contains a form, which is input surface
// regardless of the method it submits with. lowerBody must already be lowercased.
func hasFormMarkup(lowerBody string) bool {
	return strings.Contains(lowerBody, "<form")
}

// isStateChanging reports whether the method mutates server state. GET and HEAD
// do not; the executor already drops OPTIONS/TRACE/CONNECT upstream.
func isStateChanging(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// hasLegacyHandlerExtension reports whether the path names a server-executed
// handler of an older generation.
//
// Path() returns the request target from the request line, which INCLUDES any
// query string, so that is trimmed first - otherwise /x.php?next=/a.jsp would be
// judged on the query. The second check catches PATH_INFO routing
// (/index.php/users/1), which is itself a legacy shape worth the point.
func hasLegacyHandlerExtension(path string) bool {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	for i, ext := range legacyHandlerExtensions {
		if strings.HasSuffix(p, ext) || strings.Contains(p, legacyHandlerPathInfoPrefixes[i]) {
			return true
		}
	}
	return false
}

// isAuthBearing reports whether the exchange carries identity: an Authorization
// header, or a session cookie sent or set.
//
// The cookie test goes through infra.IsSessionCookieName rather than accepting
// any cookie. Bot-management and analytics cookies (__cf_bm, _ga, AWSALB) are
// set by infrastructure on responses that have no session behind them at all, so
// crediting them marked most of a CDN-fronted corpus as authenticated.
// The response half walks the header slice the caller already holds rather than
// calling resp.Cookies(). Cookies() is uncached and, before parsing anything,
// renders EVERY header to a "Name: Value" string - 888 bytes and 20 allocations
// per record, paid on the majority of records that have no session at all.
func isAuthBearing(req *httpmsg.HttpRequest, headers []httpmsg.HttpHeader) bool {
	if req.Header("Authorization") != "" {
		return true
	}
	if hasSessionCookieHeader(req.Header("Cookie")) {
		return true
	}
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if name, _, ok := strings.Cut(h.Value, "="); ok && infra.IsSessionCookieName(name) {
			return true
		}
	}
	return false
}

// hasSessionCookieHeader reports whether a request Cookie header carries at
// least one cookie whose name denotes a server-side session.
func hasSessionCookieHeader(header string) bool {
	if header == "" {
		return false
	}
	for pair := range strings.SplitSeq(header, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		if infra.IsSessionCookieName(name) {
			return true
		}
	}
	return false
}

// headersAdvertiseAuth reports whether the response head announces an
// authentication boundary: a challenge, or a redirect into a login / SSO flow.
//
// The redirect test goes through authsig, which owns the repo's login/IdP URL
// vocabulary and matches an identity provider on the parsed hostname with a
// suffix anchor. A local substring table would have matched the whole Location
// string, so `https://evil.example/?next=https://okta.com` would have counted as
// an SSO redirect.
func headersAdvertiseAuth(resp *httpmsg.HttpResponse) bool {
	if resp.Header("WWW-Authenticate") != "" {
		return true
	}
	loc := resp.Header("Location")
	if loc == "" {
		return false
	}
	u, err := url.Parse(loc)
	return err == nil && authsig.LooksLikeLoginURL(u)
}

// hasPasswordInput reports whether the body renders a password field.
// lowerBody must already be lowercased.
func hasPasswordInput(lowerBody string) bool {
	return containsAny(lowerBody, passwordInputMarkers)
}

// isNonStandardPort reports whether the endpoint answers somewhere other than
// the two ports a browser reaches by default. An explicit :443 on https (or :80
// on http) is the default written out and does not count.
func isNonStandardPort(req *httpmsg.HttpRequest) bool {
	u, err := req.URL()
	if err != nil || u == nil {
		return false
	}
	port := u.Port()
	if port == "" {
		return false
	}
	// Scheme-aware via the shared resolver, so http://host:443/ and
	// https://host:80/ both count. A bare `port != "80" && port != "443"` test
	// would call each of those standard, which is the opposite of true.
	n, err := strconv.Atoi(port)
	return err != nil || n != httpmsg.GetDefaultPort(u.Scheme)
}

// isDynamicOrigin reports whether the response is per-request rather than an
// artifact handed back by an edge cache.
//
// Positive evidence only, and a cache hit vetoes: on a host list this is what
// separates "CDN asset host" from "application", and it is one of the few such
// distinctions a single unauthenticated GET can actually make.
// The evidence is tested BEFORE the cache-hit veto. The veto can only change the
// answer when the evidence fired, which is the minority of records, so consulting
// it first spent a header scan on every record to reach the same result.
func isDynamicOrigin(resp *httpmsg.HttpResponse, hdr headerScan) bool {
	cc := strings.ToLower(resp.Header("Cache-Control"))
	dynamic := strings.Contains(cc, "no-store") || strings.Contains(cc, "private") ||
		strings.Contains(cc, "no-cache")
	if !dynamic {
		vary := strings.ToLower(resp.Header("Vary"))
		dynamic = strings.Contains(vary, "cookie") || strings.Contains(vary, "authorization")
	}
	return dynamic && !hdr.cacheHit
}

// hasPermissiveCORS reports whether the response lets an origin it does not
// control read its body.
//
// A concrete allowlisted origin with no credentials is ordinary configuration
// and earns nothing; a wildcard, a "null" origin, or credentials attached to any
// allowed origin is the shape worth ranking on. Reflection of an attacker origin
// cannot be observed here, because the probe never sends an Origin header.
func hasPermissiveCORS(resp *httpmsg.HttpResponse) bool {
	acao := strings.TrimSpace(resp.Header("Access-Control-Allow-Origin"))
	if acao == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(resp.Header("Access-Control-Allow-Credentials")), "true") {
		return true
	}
	return acao == "*" || strings.EqualFold(acao, "null")
}

// headerScan is what one walk over the response headers answers.
type headerScan struct {
	// apiHeader: a rate-limit or API-gateway header is present.
	apiHeader bool
	// debugHeader: a debug/version header is present.
	debugHeader bool
	// cacheHit: the response was served from a shared cache.
	cacheHit bool
}

// scanHeaders answers every whole-slice header question in one pass.
//
// Each question used to walk all headers itself, and two of them lowercased
// every header name to do it - 54 of the 55 allocations the header block made
// per record, on a function that runs on every record in a scan. Header names
// are canonical mixed-case, so ToLower's no-uppercase fast path never fired.
//
// The first-byte test is what makes the prefix checks cheap: every entry in
// apiHeaderPrefixes and debugHeaders starts with 'x' or 'r', which skips the
// bulk of a typical response's headers on one byte compare.
func scanHeaders(headers []httpmsg.HttpHeader) headerScan {
	var out headerScan
	for _, h := range headers {
		if h.Name == "" {
			continue
		}
		if !out.cacheHit && isCacheHitHeader(h) {
			out.cacheHit = true
		}
		switch h.Name[0] | 0x20 {
		case 'x', 'r':
		default:
			continue
		}
		if !out.apiHeader && hasAnyPrefixFold(h.Name, apiHeaderPrefixes) {
			out.apiHeader = true
		}
		if !out.debugHeader && equalsAnyFold(h.Name, debugHeaders) {
			out.debugHeader = true
		}
	}
	return out
}

// isCacheHitHeader reports whether one header says the response came from a
// shared cache. Mirrors infra.CacheState's hit rules (an explicit HIT marker, or
// a non-zero Age) for the single question this module asks, so the module can
// answer it inside its own header walk instead of paying a second one that also
// lowercases every name.
func isCacheHitHeader(h httpmsg.HttpHeader) bool {
	if strings.EqualFold(h.Name, "Age") {
		n, err := strconv.Atoi(strings.TrimSpace(h.Value))
		return err == nil && n > 0
	}
	for _, name := range cacheHitHeaders {
		if strings.EqualFold(h.Name, name) {
			return strings.Contains(strings.ToUpper(h.Value), "HIT")
		}
	}
	return false
}

// hasAnyPrefixFold reports whether s starts with any of the prefixes,
// case-insensitively and without allocating.
func hasAnyPrefixFold(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			return true
		}
	}
	return false
}

// equalsAnyFold reports whether s equals any of the names, case-insensitively.
func equalsAnyFold(s string, names []string) bool {
	for _, n := range names {
		if strings.EqualFold(s, n) {
			return true
		}
	}
	return false
}

// serverBannerLeaks reports whether the Server header names an application or
// development server, meaning the response came from an origin rather than a CDN
// or hardened reverse proxy.
func serverBannerLeaks(resp *httpmsg.HttpResponse) bool {
	server := resp.Header("Server")
	return server != "" && containsAny(strings.ToLower(server), originServerBanners)
}

// bodyLeaksInternals reports whether the body exposes the origin's own files or
// directory layout. lowerBody must already be lowercased.
//
// The directory-listing half defers to modkit.DetectDirectoryListingServer, the
// shared detector behind the active and passive directory-listing modules: it
// knows the Jetty/IIS/Apache/nginx variants and is FP-hardened against a content
// page merely titled "Index of X", which a bare substring test is not. It is
// gated behind a cheap marker first because it lowercases the whole body itself,
// and paying that on every HTML record would cost more than every other body
// scan here combined.
func bodyLeaksInternals(resp *httpmsg.HttpResponse, lowerBody string) bool {
	if strings.Contains(lowerBody, "sourcemappingurl=") {
		return true
	}
	if !containsAny(lowerBody, dirListingHints) {
		return false
	}
	return modkit.DetectDirectoryListingServer(resp.BodyToString()) != ""
}

// hasAPIPath reports whether the request path names an API route. lowerPath must
// already be lowercased. It includes any query string, which is harmless here:
// the markers are path shapes that a query cannot plausibly fake.
func hasAPIPath(lowerPath string) bool {
	return containsAny(lowerPath, apiPathMarkers) || strings.HasSuffix(lowerPath, "/api")
}

// bodyPrefixHasAPIDoc reports whether a JSON body opens like an interface
// description document. Bounded to apiDocPrefixBytes: a spec names itself in its
// first object key, and the JSON path must not pay for a full lowercase copy of
// what can be a multi-megabyte response.
func bodyPrefixHasAPIDoc(resp *httpmsg.HttpResponse) bool {
	body := resp.Body()
	if len(body) > apiDocPrefixBytes {
		body = body[:apiDocPrefixBytes]
	}
	if len(body) == 0 {
		return false
	}
	return containsAny(strings.ToLower(string(body)), apiDocMarkers)
}

// isMultipartRequest reports whether the request itself is a file upload. Split
// from hasFileInput so the request half can be decided before any body work.
func isMultipartRequest(req *httpmsg.HttpRequest) bool {
	ct := req.Header("Content-Type")
	return ct != "" && strings.Contains(strings.ToLower(ct), "multipart/form-data")
}

// hasFileInput reports whether the response offers a file upload. lowerBody must
// already be lowercased.
func hasFileInput(lowerBody string) bool {
	return strings.Contains(lowerBody, `type="file"`) ||
		strings.Contains(lowerBody, "type='file'") ||
		strings.Contains(lowerBody, "type=file")
}

// isRichHTML reports whether an HTML body carries interactive or navigational
// substance. lowerBody must already be lowercased.
//
// It deliberately does not use body size: an HTML document whose bulk is an
// inline JS bundle is large and thin at the same time, and crediting it would
// make the signal a proxy for page weight. Form inputs and links are what a
// scanner can actually act on.
func isRichHTML(lowerBody string) bool {
	if lowerBody == "" {
		return false
	}
	// Confirm it really is a document. A JSON or plain-text error page served as
	// text/html reaches here with class HTML and would otherwise be judged on
	// substring counts that mean nothing outside markup.
	if !strings.Contains(lowerBody, "<html") &&
		!strings.Contains(lowerBody, "<!doctype html") &&
		!strings.Contains(lowerBody, "<body") {
		return false
	}
	if strings.Contains(lowerBody, "<input") ||
		strings.Contains(lowerBody, "<textarea") ||
		strings.Contains(lowerBody, "<select") {
		return true
	}
	return strings.Count(lowerBody, "<a ") >= richHTMLMinAnchors
}

// isResponsive reports whether the application answered. An edge block or
// challenge is the CDN talking, not the app, and an error status is normally not
// surface worth prioritizing.
//
// The exception is an error that leaks a stack trace. A 500 dumping file paths
// and frame lines is the application talking, verbosely - the most interesting
// thing a target can do - so excluding it as "an error" would score the single
// most attackable response in a corpus the same as a blank 404. That case is
// folded in here rather than taking a signal of its own, because it is the same
// question ("did the app answer?") with a better answer.
//
// A 4xx without a trace stays neutral rather than penalized: the score floor is
// 0, so a protected 401/403 endpoint simply does not earn this signal while
// still earning the auth-bearing, JSON and tech-stack ones.
func isResponsive(resp *httpmsg.HttpResponse) bool {
	if resp == nil {
		return false
	}
	if modkit.IsEdgeBlockedResponse(resp) {
		return false
	}
	if len(resp.Body()) == 0 {
		return false
	}
	if code := resp.StatusCode(); code >= 200 && code < 400 {
		return true
	}
	return modkit.BodyHasStackTrace(resp.BodyToString())
}
