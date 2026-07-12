package httpmsg

import (
	"net/http"
	"net/url"
	"strings"
)

// CarriedSession is a browser-harvested session (cookies + optional pinned
// User-Agent) scoped to a single hostname. It is produced by the spidering
// phase (the real browser establishes a WAF/bot-cleared session) and carried
// forward into later phases — content discovery and dynamic assessment — so
// their requests inherit that cleared session instead of starting cold.
// Callers key these by hostname (same-host only), so the host is not stored.
//
// Cookies are stored pre-flattened as a Cookie header value; UserAgent is only
// set when the operator opted into a non-default User-Agent (see the runner's
// carry decision), so the honest "preset" identity is never silently replaced.
type CarriedSession struct {
	// CookieHeader is the flattened Cookie request-header value ("a=1; b=2").
	CookieHeader string
	// UserAgent is the browser User-Agent to pin on downstream requests. Empty
	// means "leave the configured User-Agent alone".
	UserAgent string
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
	switch scheme {
	case "http", "ws":
		return port == "80"
	case "https", "wss":
		return port == "443"
	}
	return false
}

// cookieDomainMatches reports whether a cookie with the given Domain attribute
// applies to host. A blank domain is a host-only cookie (applies to the exact
// host); a leading dot is ignored; parent-domain cookies (".example.com") apply
// to sub-hosts ("www.example.com").
func cookieDomainMatches(host, domain string) bool {
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return true
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// FlattenCookiesForHost filters browser-harvested cookies down to those that
// apply to host and joins them into a Cookie header value ("a=1; b=2"). The
// first value seen for a given cookie name wins; cookies for unrelated domains
// are dropped so a session stays scoped to the host it was harvested from.
// Returns "" when nothing applies.
func FlattenCookiesForHost(host string, cookies []*http.Cookie) string {
	host = NormalizeHost(host)
	if host == "" || len(cookies) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(cookies))
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c == nil || c.Name == "" {
			continue
		}
		if !cookieDomainMatches(host, c.Domain) {
			continue
		}
		if _, dup := seen[c.Name]; dup {
			continue
		}
		seen[c.Name] = struct{}{}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
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

// cookieName extracts the cookie name (portion before "=") from a "name=value"
// fragment, trimming surrounding whitespace.
func cookieName(kv string) string {
	name, _, _ := strings.Cut(kv, "=")
	return strings.TrimSpace(name)
}
