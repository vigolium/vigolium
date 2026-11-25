package httpmsg

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// CarriedCookie keeps the attributes a flat Cookie header loses. A Cookie
// request header is only names and values, so once the browser's jar has been
// flattened there is no way to tell a host-only cookie from a domain-wide one,
// a /admin cookie from a site-wide one, or a Secure cookie from one that may
// ride plain HTTP. Carrying them lets the HTTP path evaluate the jar per
// request the way a browser does, instead of attaching every harvested cookie
// to every request to the host.
type CarriedCookie struct {
	Name  string
	Value string
	// Domain is the cookie's domain WITHOUT a leading dot, lowercased. For a
	// host-only cookie it is the exact host the cookie was set on.
	Domain string
	// Path is the cookie's path attribute; "/" when the browser reported none.
	Path string
	// HostOnly is true for a cookie with no Domain attribute, which applies to
	// the exact host only and never to its subdomains. CDP reports host-only
	// cookies with a bare domain and domain cookies with a leading dot, which is
	// how the distinction survives the conversion.
	HostOnly bool
	// Secure restricts the cookie to https (and, per RFC 6265bis, trustworthy
	// origins; this evaluates scheme only, which is what the scanner can see).
	Secure bool
	// Expires is the cookie's expiry. A zero value is a session cookie, which
	// never expires on its own within a scan.
	Expires time.Time
}

// CarriedSession is a browser-harvested session (cookies + optional pinned
// User-Agent) scoped to a single hostname. It is produced by the spidering
// phase (the real browser establishes a WAF/bot-cleared session) and carried
// forward into later phases — content discovery and dynamic assessment — so
// their requests inherit that cleared session instead of starting cold.
// Callers key these by hostname (same-host only), so the host is not stored.
//
// Cookies carries the harvested jar with its attributes intact and is what
// CookieHeaderFor evaluates; CookieHeader is the pre-flattened fallback for a
// harvest that recorded no attributes. UserAgent is only set when the operator
// opted into a non-default User-Agent (see the runner's carry decision), so the
// honest "preset" identity is never silently replaced.
type CarriedSession struct {
	// CookieHeader is the flattened Cookie request-header value ("a=1; b=2").
	// It is the fallback for sessions harvested without attributes (Cookies
	// empty), and a reasonable summary of the session for logging.
	CookieHeader string
	// Cookies is the harvested jar with the attributes a flat header loses.
	// When non-empty it is authoritative: CookieHeaderFor evaluates it per
	// request rather than sending CookieHeader verbatim.
	Cookies []CarriedCookie
	// UserAgent is the browser User-Agent to pin on downstream requests. Empty
	// means "leave the configured User-Agent alone".
	UserAgent string
	// BrowserUserAgent is the User-Agent the harvesting browser presented,
	// recorded for a caller that replays the cookies itself (an edge clearance
	// is bound to it). Never applied to a request; UserAgent is what is pinned.
	BrowserUserAgent string
	// AuthorizationHeader is a token-based session credential (e.g. "Bearer <jwt>")
	// harvested from the crawl's authenticated traffic. Token-based SPAs (Juice
	// Shop, most JWT apps) keep the session in localStorage and send it as an
	// Authorization header rather than a cookie, so carrying only cookies leaves the
	// scan unauthenticated. Applied only when the outgoing request has no
	// Authorization of its own, and before the operator's -H headers so an explicit
	// -H Authorization still wins. Empty means "carry no token".
	AuthorizationHeader string
	// Origin is the normalized origin (scheme://host[:port]) the token was harvested
	// from. Bearer tokens are origin-scoped (scheme+host+port), unlike cookies, so the
	// AuthorizationHeader is attached only to requests whose origin matches this — a
	// token minted for https://host:3000 must not leak to http://host:8080 on the same
	// hostname. Empty means "no origin recorded": fall back to hostname-only scoping
	// (the pre-origin behavior) so older harvests keep working.
	Origin string
}

// NormalizeHost lowercases a host and strips any port, returning the bare
// hostname used as the CarriedSession key and the request-match key. Delegates
// port-stripping to the package's IPv6-aware extractHostname.
func NormalizeHost(host string) string {
	return strings.ToLower(extractHostname(strings.TrimSpace(host)))
}

// HostnameFromURL parses a URL string and returns its lowercased, port-stripped
// hostname, or "" when it has no host. Used to scope carried sessions to the
// exact host they were harvested from.
func HostnameFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return NormalizeHost(u.Hostname())
}

// OriginFromURL returns the normalized origin (scheme://host[:port]) of raw, or ""
// when it has no scheme+host. A default port for the scheme is dropped so origins
// compare equal regardless of an explicit vs implicit default port.
func OriginFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return ""
	}
	return normalizedOrigin(u.Scheme, u.Hostname(), u.Port())
}

// OriginMatchesURL reports whether u has the same origin (scheme, host, port) as the
// normalized origin string produced by OriginFromURL. An empty origin or nil URL
// never matches.
func OriginMatchesURL(origin string, u *url.URL) bool {
	if origin == "" || u == nil {
		return false
	}
	return origin == normalizedOrigin(u.Scheme, u.Hostname(), u.Port())
}

// normalizedOrigin builds "scheme://host[:port]" with scheme and host lowercased and
// the port dropped when it is the scheme default, so an explicit default port
// compares equal to an implicit one.
func normalizedOrigin(scheme, host, port string) string {
	scheme = strings.ToLower(scheme)
	host = strings.ToLower(host)
	if port != "" && isDefaultPort(scheme, port) {
		port = ""
	}
	if port == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// isDefaultPort reports whether port is the well-known default for scheme.
func isDefaultPort(scheme, port string) bool {
	return GetDefaultPort(scheme) == parsePort(port)
}

// cookieDomainMatches reports whether a cookie with the given Domain attribute
// applies to host. A blank domain is a host-only cookie (applies to the exact
// host); a leading dot is ignored; parent-domain cookies (".example.com") apply
// to sub-hosts ("www.example.com").
//
// A bare domain is treated as domain-wide here, which is LOOSER than RFC 6265:
// it cannot distinguish host-only from domain-wide because *http.Cookie has no
// host-only bit. CarriedCookie.HostOnly carries that bit, and
// carriedDomainMatches below is the precise version used once it is known.
func cookieDomainMatches(host, domain string) bool {
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return true
	}
	return host == domain || isSubdomainOf(host, domain)
}

// isSubdomainOf reports whether host sits under domain — i.e. host ends with
// "."+domain — without building that string. Called once per cookie per
// outgoing request, which is why the concatenation is worth avoiding.
func isSubdomainOf(host, domain string) bool {
	cut := len(host) - len(domain) - 1
	return cut > 0 && host[cut] == '.' && host[cut+1:] == domain
}

// carriedDomainMatches is RFC 6265 §5.1.3 domain-matching with the host-only
// flag honoured: a host-only cookie applies to the exact host and nothing else;
// a domain cookie applies to that domain and any sub-host of it.
func carriedDomainMatches(host string, c CarriedCookie) bool {
	domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
	if domain == "" {
		// No domain recorded at all: treat it as belonging to the host the
		// session is keyed by, which is the only host it can be sent to.
		return true
	}
	if host == domain {
		return true
	}
	if c.HostOnly {
		return false
	}
	return isSubdomainOf(host, domain)
}

// cookiePathMatches is RFC 6265 §5.1.4 path-matching: the cookie's path is a
// prefix of the request path, and the match ends either at a "/" in the cookie
// path or at a "/" in the request path. So a cookie for /admin is sent to
// /admin and /admin/users but not to /administrator.
func cookiePathMatches(requestPath, cookiePath string) bool {
	if cookiePath == "" {
		cookiePath = "/"
	}
	if requestPath == "" {
		requestPath = "/"
	}
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	if strings.HasSuffix(cookiePath, "/") {
		return true
	}
	return requestPath[len(cookiePath)] == '/'
}

// cookieExpired reports whether c has a non-zero expiry that is not in the
// future. A zero expiry is a session cookie: it lives as long as the browser
// profile did, which for a scan is the whole scan.
func cookieExpired(c CarriedCookie, now time.Time) bool {
	return !c.Expires.IsZero() && !c.Expires.After(now)
}

// CarriedCookiesFromHTTP converts a browser-harvested jar into CarriedCookies
// scoped to host, keeping the attributes a flat Cookie header loses. Cookies
// that do not apply to host are dropped (a session is only ever sent to the
// host it was harvested from), as are nameless and expired ones.
//
// The host-only bit is recovered from the Domain attribute: CDP reports a
// host-only cookie with a bare domain ("example.com") and a domain cookie with
// a leading dot (".example.com"). A cookie with no domain at all is treated as
// host-only on host, which is the narrowest honest reading.
func CarriedCookiesFromHTTP(host string, cookies []*http.Cookie) []CarriedCookie {
	host = NormalizeHost(host)
	if host == "" || len(cookies) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]CarriedCookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		raw := strings.ToLower(strings.TrimSpace(c.Domain))
		hostOnly := !strings.HasPrefix(raw, ".")
		domain := strings.TrimPrefix(raw, ".")
		if domain == "" {
			domain = host
			hostOnly = true
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		cc := CarriedCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   domain,
			Path:     path,
			HostOnly: hostOnly,
			Secure:   c.Secure,
			Expires:  c.Expires,
		}
		if !carriedDomainMatches(host, cc) || cookieExpired(cc, now) {
			continue
		}
		out = append(out, cc)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// CookieHeaderFor evaluates the carried jar for ONE outgoing URL the way a
// browser would (RFC 6265 §5.4): host-only cookies need an exact host match and
// domain cookies a domain match; the path must match; a Secure cookie is only
// sent over https; expired cookies are dropped; longer paths come first.
//
// A session harvested before attributes were recorded has no Cookies, and falls
// back to the pre-flattened CookieHeader — so older harvests keep working
// exactly as they did.
//
// Where a browser would send two cookies of the same name (one per path), this
// sends only the most specific. The carried session leaves here as a single
// flat header and MergeCookieHeaders dedups by name downstream, so the second
// copy would be dropped there regardless; keeping the longest-path one makes
// that choice deliberate rather than positional.
func (s CarriedSession) CookieHeaderFor(u *url.URL, now time.Time) string {
	if len(s.Cookies) == 0 {
		return s.CookieHeader
	}
	if u == nil {
		return ""
	}
	host := NormalizeHost(u.Hostname())
	if host == "" {
		return ""
	}
	secureOK := strings.EqualFold(u.Scheme, "https")
	path := u.Path
	if path == "" {
		path = "/"
	}
	return joinCarriedCookies(s.Cookies, now, longestPathFirst, func(c CarriedCookie) bool {
		return carriedDomainMatches(host, c) &&
			cookiePathMatches(path, c.Path) &&
			(!c.Secure || secureOK)
	})
}

// CookieHeaderForOrigin evaluates the carried jar for an ORIGIN, ignoring path:
// it is for callers that configure one static Cookie header for a whole target
// (the content-discovery engine) and so have no single request path to match.
// Domain and Secure are still honoured — a Secure cookie must not be handed to
// an http crawl of the same host.
//
// With no path to match, a duplicated cookie name keeps its BROADEST (shortest)
// path, the copy most likely to apply to an arbitrary path on the origin.
func (s CarriedSession) CookieHeaderForOrigin(scheme, host string, now time.Time) string {
	if len(s.Cookies) == 0 {
		return s.CookieHeader
	}
	host = NormalizeHost(host)
	if host == "" {
		return ""
	}
	secureOK := strings.EqualFold(scheme, "https")
	return joinCarriedCookies(s.Cookies, now, broadestPathFirst, func(c CarriedCookie) bool {
		return carriedDomainMatches(host, c) && (!c.Secure || secureOK)
	})
}

// cookieOrder picks which of two matching same-name cookies is preferred, and
// the order the header is written in.
type cookieOrder int

const (
	// longestPathFirst is RFC 6265 §5.4 ordering for a known request path.
	longestPathFirst cookieOrder = iota
	// broadestPathFirst prefers the most widely applicable cookie, for callers
	// with no request path.
	broadestPathFirst
)

// joinCarriedCookies filters cookies through keep, drops expired ones, orders
// them per order, keeps one cookie per name (the first in that order), and joins
// the result into a Cookie header value. Returns "" when nothing applies.
func joinCarriedCookies(cookies []CarriedCookie, now time.Time, order cookieOrder, keep func(CarriedCookie) bool) string {
	matched := make([]CarriedCookie, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == "" || cookieExpired(c, now) || !keep(c) {
			continue
		}
		matched = append(matched, c)
	}
	if len(matched) == 0 {
		return ""
	}
	// Stable, so harvest position remains the tie-break (RFC 6265: creation
	// time) without carrying an index alongside each cookie. SortStableFunc
	// rather than sort.SliceStable because this runs on every outgoing request
	// and the reflect-based swapper allocates.
	slices.SortStableFunc(matched, func(a, b CarriedCookie) int {
		la, lb := cookiePathLen(a.Path), cookiePathLen(b.Path)
		if order == longestPathFirst {
			return lb - la
		}
		return la - lb
	})
	// Dedup by name over a list that is at most a jar's worth of cookies, so a
	// linear scan of what has already been emitted beats allocating a map.
	var b strings.Builder
	names := make([]string, 0, len(matched))
	for _, c := range matched {
		if slices.Contains(names, c.Name) {
			continue
		}
		names = append(names, c.Name)
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		b.WriteString(c.Value)
	}
	return b.String()
}

// FlattenCookiesForHost filters browser-harvested cookies down to those that
// apply to host and joins them into a Cookie header value ("a=1; b=2").
// Cookies for unrelated domains are dropped so a session stays scoped to the
// host it was harvested from, as are expired ones. For a duplicated name the
// BROADEST (shortest) path wins: the result is one static header for the whole
// host, so the cookie most likely to apply to an arbitrary path is the right
// one to keep — previously it was whichever the browser happened to list first.
//
// This is the attribute-losing flattening; it stays because a flat header is
// what several callers still want (and what CarriedSession.CookieHeader is).
// Per-request evaluation belongs in CarriedSession.CookieHeaderFor.
func FlattenCookiesForHost(host string, cookies []*http.Cookie) string {
	host = NormalizeHost(host)
	if host == "" || len(cookies) == 0 {
		return ""
	}
	now := time.Now()
	matched := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		if !cookieDomainMatches(host, c.Domain) {
			continue
		}
		if !c.Expires.IsZero() && !c.Expires.After(now) {
			continue
		}
		matched = append(matched, c)
	}
	if len(matched) == 0 {
		return ""
	}
	// Same filter → stable sort by path → dedup by name → join shape as
	// joinCarriedCookies above, over *http.Cookie instead of CarriedCookie.
	// Broadest path first, so the duplicate dropped below is the narrower one.
	slices.SortStableFunc(matched, func(a, b *http.Cookie) int {
		return cookiePathLen(a.Path) - cookiePathLen(b.Path)
	})
	var b strings.Builder
	names := make([]string, 0, len(matched))
	for _, c := range matched {
		if slices.Contains(names, c.Name) {
			continue
		}
		names = append(names, c.Name)
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		b.WriteString(c.Value)
	}
	return b.String()
}

// cookiePathLen is the specificity of a cookie path, with an unset path
// counting as the site-wide "/" rather than as something even broader — so an
// unset path and an explicit "/" rank together instead of sorting apart.
func cookiePathLen(path string) int {
	if path == "" {
		return 1
	}
	return len(path)
}

// MergeCookieHeaders returns a Cookie header value that keeps every cookie in
// existing and appends any cookie from carried whose name is not already
// present. Existing cookies always win — a request that already carries a
// cookie (e.g. a browser-crawled record) is never overwritten, we only add the
// clearance/session cookies it is missing.
func MergeCookieHeaders(existing, carried string) string {
	existing = strings.TrimSpace(existing)
	carried = strings.TrimSpace(carried)
	if existing == "" {
		return carried
	}
	if carried == "" {
		return existing
	}
	have := make(map[string]struct{})
	for _, kv := range strings.Split(existing, ";") {
		if name := cookieName(kv); name != "" {
			have[name] = struct{}{}
		}
	}
	var additions []string
	for _, kv := range strings.Split(carried, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name := cookieName(kv)
		if name == "" {
			continue
		}
		if _, ok := have[name]; ok {
			continue
		}
		have[name] = struct{}{}
		additions = append(additions, kv)
	}
	if len(additions) == 0 {
		return existing
	}
	return strings.TrimRight(existing, "; ") + "; " + strings.Join(additions, "; ")
}

// OverrideCookieHeaders is MergeCookieHeaders with the opposite precedence:
// each cookie in override replaces the same-named cookie in existing (names
// compared case-insensitively) in place, or is appended when absent. The
// result is re-joined with "; ".
func OverrideCookieHeaders(existing, override string) string {
	var parts []string
	for _, kv := range strings.Split(existing, ";") {
		if kv = strings.TrimSpace(kv); kv != "" {
			parts = append(parts, kv)
		}
	}
	for _, kv := range strings.Split(override, ";") {
		kv = strings.TrimSpace(kv)
		name := cookieName(kv)
		if name == "" {
			continue
		}
		replaced := false
		for i, have := range parts {
			if strings.EqualFold(cookieName(have), name) {
				parts[i] = kv
				replaced = true
				break
			}
		}
		if !replaced {
			parts = append(parts, kv)
		}
	}
	return strings.Join(parts, "; ")
}

// cookieName extracts the cookie name (portion before "=") from a "name=value"
// fragment, trimming surrounding whitespace.
func cookieName(kv string) string {
	name, _, _ := strings.Cut(kv, "=")
	return strings.TrimSpace(name)
}
