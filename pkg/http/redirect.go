package http

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/authsig"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/reconsig"
	"github.com/vigolium/vigolium/pkg/types"
)

// Redirect modes accepted by Options.RedirectMode / --redirect-mode.
//
// These replace the FollowRedirects/FollowHostRedirects bool pair, which had no
// spelling for the case a host sweep needs: follow inside the registrable
// domain. `www.example.com -> example.com` is the same application answering
// under its canonical name, while `example.com -> tracker.example.net` is a
// different party — and exact-host matching cannot tell those apart, so the
// only options were "follow everything" or "follow nothing".
const (
	// RedirectModeOff records the 3xx itself and never follows it.
	RedirectModeOff = "off"
	// RedirectModeSameHost follows only when scheme-host-port is unchanged.
	RedirectModeSameHost = "same-host"
	// RedirectModeSameApex follows while the registrable domain (eTLD+1) is
	// unchanged. Cross-scheme and cross-port hops within that domain follow.
	RedirectModeSameApex = "same-apex"
	// RedirectModeInScope follows a hop only when its host is inside the scan's
	// scope (Services.HopScope, installed by the runner from the scope
	// matcher). With no scope installed (a library caller, a bare requester)
	// it behaves as same-apex. This is the default (SAFE-2): a redirect is a
	// request to a new destination, and "any" sent scan traffic — payloads
	// included — to whatever host a target named.
	RedirectModeInScope = "in-scope"
	// RedirectModeAny follows every redirect up to the hop cap. It was the
	// historical default.
	RedirectModeAny = "any"
)

// RedirectModes lists every accepted spelling, in the order help text should
// present them (most restrictive first). Error messages derive from this rather
// than hand-listing, so a mode added here reaches the CLI for free.
var RedirectModes = []string{
	RedirectModeOff,
	RedirectModeSameHost,
	RedirectModeSameApex,
	RedirectModeInScope,
	RedirectModeAny,
}

// ValidRedirectMode reports whether s names a redirect mode.
func ValidRedirectMode(s string) bool {
	return slices.Contains(RedirectModes, strings.ToLower(strings.TrimSpace(s)))
}

// ResolveRedirectMode collapses the redirect options into one mode.
//
// An explicit RedirectMode always wins. Otherwise the legacy bools are mapped
// so nothing that set them changes behaviour: DisableRedirects means off,
// FollowHostRedirects means same-host, and anything else means any — which is
// what the old makeRedirectFunc(false, n) already did, since it only ever
// refused on the hop cap.
func ResolveRedirectMode(options *types.Options) string {
	if options == nil {
		return RedirectModeInScope
	}
	if m := strings.ToLower(strings.TrimSpace(options.RedirectMode)); m != "" {
		if ValidRedirectMode(m) {
			return m
		}
		// An unrecognised value is caught at flag-validation time; falling back
		// to the default here keeps a library caller that set it by hand from
		// silently getting "follow nothing".
		return RedirectModeInScope
	}
	switch {
	case options.DisableRedirects:
		return RedirectModeOff
	case options.FollowHostRedirects:
		return RedirectModeSameHost
	default:
		return RedirectModeInScope
	}
}

// crossHostKeepHeaders are the only request headers that survive a redirect
// hop to a different host:port (SAFE-2). Everything else — session and -H
// credentials, API keys, module-owned headers, tracing ids — stays with the
// host it was meant for. Go itself strips only Authorization and Cookie, and
// only across domains, so `-H "X-API-Key: …"` used to reach any Location.
var crossHostKeepHeaders = map[string]bool{
	"User-Agent":     true,
	"Content-Type":   true,
	"Content-Length": true,
}

// stripCrossHostHeaders drops every header except crossHostKeepHeaders and
// Accept* from a hop request.
func stripCrossHostHeaders(h http.Header) {
	for name := range h {
		canon := http.CanonicalHeaderKey(name)
		if crossHostKeepHeaders[canon] || strings.HasPrefix(canon, "Accept") {
			continue
		}
		delete(h, name)
	}
}

// makeRedirectFunc builds the http.Client CheckRedirect policy for mode.
//
// via[0] is the ORIGINAL request, not the previous hop: a chain that walks
// a.example -> b.example -> c.example is judged against a.example at every
// step. That is deliberate for same-apex — otherwise a chain could walk off
// its starting domain one hop at a time, each hop looking legitimate relative
// to the one before it.
func makeRedirectFunc(mode string, maxRedirects int) func(*http.Request, []*http.Request) error {
	return makeScopedRedirectFunc(mode, maxRedirects, nil)
}

// makeScopedRedirectFunc is makeRedirectFunc with the scan's hop scope. scope
// is read per hop (the runner installs it on Services after the requester is
// built); a nil getter or a nil result means "no scope known", under which
// in-scope degrades to same-apex. A followed hop to a different host:port has
// its headers stripped to crossHostKeepHeaders in every mode.
func makeScopedRedirectFunc(mode string, maxRedirects int, scope func() func(host string) bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		if mode == RedirectModeOff {
			return http.ErrUseLastResponse
		}
		// The authentication gate runs BEFORE the host rule, and applies to
		// every mode, because no host rule can express it. See stopsAtAuthWall.
		if stopsAtAuthWall(via[0].URL, req.URL) {
			return http.ErrUseLastResponse
		}
		switch mode {
		case RedirectModeSameHost:
			if req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
		case RedirectModeSameApex:
			if !sameRegistrableDomain(via[0].URL.Host, req.URL.Host) {
				return http.ErrUseLastResponse
			}
		case RedirectModeInScope:
			var inScope func(string) bool
			if scope != nil {
				inScope = scope()
			}
			if inScope != nil {
				if !inScope(req.URL.Hostname()) {
					return http.ErrUseLastResponse
				}
			} else if !sameRegistrableDomain(via[0].URL.Host, req.URL.Host) {
				return http.ErrUseLastResponse
			}
		}
		if httpmsg.URLHostPort(req.URL) != httpmsg.URLHostPort(via[0].URL) {
			stripCrossHostHeaders(req.Header)
		}
		return nil
	}
}

// stopsAtAuthWall reports whether a hop from origin to dest walks into a
// login / SSO wall that the scan must not follow.
//
// This exists because the host-based modes structurally cannot express it. The
// three commonest authentication bounces are all reachable under same-apex, and
// two of them never leave the host at all:
//
//	app.example.com -> login.example.com/oauth2/authorize   (same apex)
//	app.example.com -> app.example.com/.auth/login/aad      (Azure EasyAuth)
//	app.example.com -> app.example.com/cdn-cgi/access/login (Cloudflare Access)
//
// Following any of them hands every passive and active module the identity
// provider's login page while the record, the findings and matched_at all still
// name the target — a report whose every line is about somebody else's server
// and which the target's owner cannot reproduce. The browser crawler has
// refused these since it learned to (crawler.evaluateStartRedirect); this is
// the same rule for the transport every other phase fetches through.
//
// Stopping means ErrUseLastResponse, so the 3xx itself becomes the response the
// caller sees, Location intact. That is strictly more informative than the
// login page: "this target is behind <wall>" is the finding, and callers that
// want the wall's host read it off Location.
//
// The origin is exempted when it already looks like an authentication endpoint.
// An operator who points the scanner AT an IdP means to scan the IdP, and every
// hop inside a login flow matches the same signatures — gating those would stop
// such a scan on its first redirect.
// Destination first: it is the discriminating test and it fails for almost
// every hop, so the origin — which is constant across a chain and therefore
// re-tested on every one of up to ten hops — is only examined when the
// destination already looks like a wall.
func stopsAtAuthWall(origin, dest *url.URL) bool {
	if origin == nil || dest == nil {
		return false
	}
	if !authsig.LooksLikeLoginURL(dest) {
		return false
	}
	return !authsig.LooksLikeLoginURL(origin)
}

// StoppedAtAuthWall reports whether resp is a redirect the policy refused to
// follow because its destination is a login / SSO wall, and returns that
// destination.
//
// Callers use this to attribute the stop rather than to make it: the decision
// already happened inside CheckRedirect, which can only signal through
// ErrUseLastResponse and therefore cannot report a reason.
//
// Re-deriving beats recording it inside the policy, which would be the obvious
// alternative, because the request clusterer replays a cached response WITHOUT
// running CheckRedirect at all — anything the policy recorded would be silently
// absent on every cache hit. Reading it back off the stored 3xx is uniform
// across live and replayed responses, and costs one URL parse on a path already
// gated to redirects.
//
// Sharing stopsAtAuthWall with the policy is what keeps the two from drifting
// into disagreeing about what a wall is.
func StoppedAtAuthWall(requestURL string, statusCode int, location string) (string, bool) {
	if statusCode < 300 || statusCode >= 400 || location == "" {
		return "", false
	}
	base, err := url.Parse(requestURL)
	if err != nil {
		return "", false
	}
	dest, err := base.Parse(location)
	if err != nil {
		return "", false
	}
	if !stopsAtAuthWall(base, dest) {
		return "", false
	}
	return dest.String(), true
}

// sameRegistrableDomain reports whether two hosts share an eTLD+1.
//
// Fails CLOSED: when either host has no resolvable registrable domain (a bare
// IP, an internal single-label name like "intranet", an unparseable host), the
// answer is exact-host equality. Following a redirect is a request to a new
// destination, so "I could not tell" must not resolve to "go ahead" — an IP
// literal in particular has no apex at all, and treating an unresolvable pair
// as same-apex would make every such hop follow unconditionally.
func sameRegistrableDomain(fromHost, toHost string) bool {
	// reconsig normalizes (lowercase, trim, strip port) on the way in, so both
	// helpers are handed the raw host as-is.
	fromAPEX := reconsig.RegistrableDomain(fromHost)
	toAPEX := reconsig.RegistrableDomain(toHost)
	if fromAPEX == "" || toAPEX == "" {
		// Compare the bare hostnames (port stripped) so a bare-IP target that
		// redirects to itself on another port still follows.
		return reconsig.HostOf(fromHost) == reconsig.HostOf(toHost)
	}
	return fromAPEX == toAPEX
}

// canonicalHop reports whether dest is the same resource as origin under its
// canonical spelling — a scheme upgrade, a trailing slash, www. gained or
// dropped, a default port made explicit, or any combination.
//
// It is the question ShapeRedirectChain asks to decide whether a hop earns a
// row, and the only question anything asks about a hop's meaning, so it is a
// predicate rather than a classification: an exported three-valued taxonomy
// would be a promise to callers that do not exist.
//
// An authentication wall is never canonical, however well the spelling lines
// up. A site that bounces /app to /app/ and straight into Cloudflare Access
// produces a hop that satisfies every spelling test, and collapsing it would
// hide the one hop an operator most needs to see.
func canonicalHop(origin, dest *url.URL) bool {
	if origin == nil || dest == nil {
		return false
	}
	if stopsAtAuthWall(origin, dest) {
		return false
	}
	return canonicalHost(origin) == canonicalHost(dest) &&
		canonicalPath(origin) == canonicalPath(dest) &&
		origin.RawQuery == dest.RawQuery
}

// canonicalHost reduces a host to the identity a canonicalising hop preserves:
// lowercased, default port removed, leading "www." removed.
//
// Dropping "www." is the one judgement call here. apex -> www is the commonest
// redirect on the web and is the same application every time; treating it as a
// relocation would leave the collapse doing nothing on the majority of real
// hosts. A hop between two OTHER subdomains is still a relocation, because
// "www" is the only label with this convention behind it.
func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	port := u.Port()
	// httpmsg owns the scheme -> default-port table; re-deriving 80/443 here
	// would be the fifth copy of it in the tree.
	if port == "" || port == strconv.Itoa(httpmsg.GetDefaultPort(strings.ToLower(u.Scheme))) {
		return host
	}
	return host + ":" + port
}

// canonicalPath reduces a path to the identity a trailing-slash hop preserves.
// "" and "/" are the same resource; "/a" and "/a/" are the same resource to a
// redirect that only added the slash.
func canonicalPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			return "/"
		}
	}
	return p
}
