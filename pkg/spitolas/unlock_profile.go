package spitolas

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// UnlockProfile is the client state an unlock walk forges before it visits a
// single-page app's routes: storage seeds, cookies and response stubs for the
// app's own bootstrap and permission calls. The caller (a model reading the
// app's bundle) decides how the app's client-side gate works and writes the
// profile; UnlockWalk only applies it.
//
// The JSON keys are camelCase: the shape is shared with gimorra's
// UnlockProfile schema. ParseUnlockProfile is the only way in, so every
// profile UnlockWalk sees has passed Validate.
type UnlockProfile struct {
	// Origin is the app's origin (scheme://host[:port]); every stub and route
	// lives on it.
	Origin string `json:"origin"`
	// LocalStorage and SessionStorage are written on Origin before the app's
	// own scripts run, in every document the walk loads.
	LocalStorage   map[string]string `json:"localStorage,omitempty"`
	SessionStorage map[string]string `json:"sessionStorage,omitempty"`
	// Cookies are set host-only on Origin before the first navigation.
	Cookies []UnlockCookie `json:"cookies,omitempty"`
	// Stubs answer matching same-origin requests in the browser; a stubbed
	// request never reaches the target and its response is never stored.
	Stubs []UnlockStub `json:"stubs,omitempty"`
	// Routes are visited in order after Origin's root, each a path (or
	// absolute URL) on Origin, taken verbatim.
	Routes []string `json:"routes,omitempty"`
	// MaxRoutes caps how many Routes are visited (default 40, at most 200).
	MaxRoutes int `json:"maxRoutes,omitempty"`
	// SettleMs bounds the wait for the network to go idle after each
	// navigation (default 2500, at most 10000).
	SettleMs int `json:"settleMs,omitempty"`
}

// UnlockCookie is one cookie an unlock profile sets.
type UnlockCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Path  string `json:"path,omitempty"`
}

// UnlockStub is one forged response. Path is an exact path, a template whose
// segments ":name" or "{name}" match any one non-empty segment, or an absolute
// URL on the profile's origin. The query string is not matched.
type UnlockStub struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
	Body        string `json:"body,omitempty"`
}

// Unlock profile bounds. Each bounds what one profile can make the walk hold
// in memory or inject into a page; none is a judgement about the target.
const (
	DefaultUnlockMaxRoutes = 40
	MaxUnlockRoutes        = 200
	DefaultUnlockSettleMs  = 2500
	MaxUnlockSettleMs      = 10000

	maxUnlockProfileBytes  = 4 << 20
	maxUnlockStorageItems  = 200
	maxUnlockStorageKey    = 256
	maxUnlockStorageBytes  = 256 << 10 // per store, keys plus values
	maxUnlockCookies       = 50
	maxUnlockCookieValue   = 4096
	maxUnlockStubs         = 100
	MaxUnlockStubBody      = 64 << 10
	maxUnlockRouteLen      = 2048
	maxUnlockContentTypeLn = 200
)

// ErrInvalidUnlockProfile wraps every profile rejection.
var ErrInvalidUnlockProfile = errors.New("invalid unlock profile")

func profileErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidUnlockProfile, fmt.Sprintf(format, args...))
}

// ParseUnlockProfile decodes data strictly (an unknown key such as a
// misspelt "localStore" is an error rather than silently ignored; key case is
// not significant, as everywhere in encoding/json), fills the defaults and
// validates the result.
func ParseUnlockProfile(data []byte) (*UnlockProfile, error) {
	if len(data) > maxUnlockProfileBytes {
		return nil, profileErr("the profile is %d bytes, over the %d-byte limit", len(data), maxUnlockProfileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p UnlockProfile
	if err := dec.Decode(&p); err != nil {
		return nil, profileErr("not a JSON unlock profile: %v", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, profileErr("trailing data after the profile object")
	}
	if p.MaxRoutes == 0 {
		p.MaxRoutes = DefaultUnlockMaxRoutes
	}
	if p.SettleMs == 0 {
		p.SettleMs = DefaultUnlockSettleMs
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks every bound and confinement rule: Origin is a bare http(s)
// origin, every stub and route is on it, and every size is within its limit.
// It normalises Origin (lowercase scheme and host, no trailing slash).
func (p *UnlockProfile) Validate() error {
	origin, err := parseUnlockOrigin(p.Origin)
	if err != nil {
		return err
	}
	p.Origin = origin.String()
	if p.MaxRoutes < 1 || p.MaxRoutes > MaxUnlockRoutes {
		return profileErr("maxRoutes %d is outside 1..%d", p.MaxRoutes, MaxUnlockRoutes)
	}
	if p.SettleMs < 1 || p.SettleMs > MaxUnlockSettleMs {
		return profileErr("settleMs %d is outside 1..%d", p.SettleMs, MaxUnlockSettleMs)
	}
	for name, store := range map[string]map[string]string{"localStorage": p.LocalStorage, "sessionStorage": p.SessionStorage} {
		if err := validateUnlockStorage(name, store); err != nil {
			return err
		}
	}
	if len(p.Cookies) > maxUnlockCookies {
		return profileErr("%d cookies, over the limit of %d", len(p.Cookies), maxUnlockCookies)
	}
	for i, c := range p.Cookies {
		if err := validateUnlockCookie(c); err != nil {
			return profileErr("cookies[%d]: %v", i, err)
		}
	}
	if len(p.Stubs) > maxUnlockStubs {
		return profileErr("%d stubs, over the limit of %d", len(p.Stubs), maxUnlockStubs)
	}
	for i := range p.Stubs {
		if err := p.validateStub(&p.Stubs[i], origin); err != nil {
			return profileErr("stubs[%d]: %v", i, err)
		}
	}
	if len(p.Routes) > MaxUnlockRoutes {
		return profileErr("%d routes, over the hard cap of %d", len(p.Routes), MaxUnlockRoutes)
	}
	for i, r := range p.Routes {
		if _, err := resolveUnlockRoute(origin, r); err != nil {
			return profileErr("routes[%d] %q: %v", i, r, err)
		}
	}
	return nil
}

// NormalizeUnlockOrigin returns raw in the form Validate gives a profile's
// origin, or the error Validate would report for it.
func NormalizeUnlockOrigin(raw string) (string, error) {
	u, err := parseUnlockOrigin(raw)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// parseUnlockOrigin reads a bare http(s) origin: no path beyond "/", no
// query, fragment or userinfo.
func parseUnlockOrigin(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, profileErr("origin is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, profileErr("origin %q is not a URL: %v", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, profileErr("origin %q must be an http:// or https:// origin", raw)
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, profileErr("origin %q must be scheme://host[:port] with no path, query, fragment or credentials", raw)
	}
	host := strings.ToLower(u.Host)
	// The browser writes an origin without its scheme's default port
	// (location.origin), and the seed script compares against that form.
	if port := u.Port(); (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		host = strings.TrimSuffix(host, ":"+port)
	}
	return &url.URL{Scheme: scheme, Host: host}, nil
}

// sameUnlockOrigin reports whether u is on origin (scheme, host and port, a
// scheme's default port written or not).
func sameUnlockOrigin(origin, u *url.URL) bool {
	o := httpmsg.URLOrigin(u)
	return o != "" && o == httpmsg.URLOrigin(origin)
}

// Targets is every URL a walk of p navigates to, in order: the origin's root,
// then each route resolved on the origin (all of Routes, not only the first
// MaxRoutes).
func (p *UnlockProfile) Targets() []string {
	origin, err := parseUnlockOrigin(p.Origin)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(p.Routes)+1)
	out = append(out, origin.ResolveReference(&url.URL{Path: "/"}).String())
	for _, r := range p.Routes {
		if u, err := resolveUnlockRoute(origin, r); err == nil {
			out = append(out, u.String())
		}
	}
	return out
}

// resolveUnlockRoute resolves a route against origin and refuses one that
// lands anywhere else.
func resolveUnlockRoute(origin *url.URL, route string) (*url.URL, error) {
	if strings.TrimSpace(route) == "" {
		return nil, errors.New("empty route")
	}
	if len(route) > maxUnlockRouteLen {
		return nil, fmt.Errorf("longer than %d bytes", maxUnlockRouteLen)
	}
	if strings.ContainsFunc(route, unicode.IsControl) {
		return nil, errors.New("contains a control character")
	}
	ref, err := url.Parse(route)
	if err != nil {
		return nil, fmt.Errorf("not a URL path: %w", err)
	}
	u := origin.ResolveReference(ref)
	if !sameUnlockOrigin(origin, u) || u.User != nil {
		return nil, fmt.Errorf("not on the profile origin %s", origin)
	}
	return u, nil
}

func validateUnlockStorage(name string, store map[string]string) error {
	if len(store) > maxUnlockStorageItems {
		return profileErr("%s has %d entries, over the limit of %d", name, len(store), maxUnlockStorageItems)
	}
	total := 0
	for k, v := range store {
		if k == "" || len(k) > maxUnlockStorageKey {
			return profileErr("%s key %q must be 1..%d bytes", name, k, maxUnlockStorageKey)
		}
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			return profileErr("%s entry %q is not valid UTF-8", name, k)
		}
		total += len(k) + len(v)
	}
	if total > maxUnlockStorageBytes {
		return profileErr("%s holds %d bytes, over the limit of %d", name, total, maxUnlockStorageBytes)
	}
	return nil
}

// validateUnlockCookie checks a cookie against RFC 6265's grammar: the name a
// token, the value free of the characters that end or split a cookie.
func validateUnlockCookie(c UnlockCookie) error {
	if !isHTTPToken(c.Name) {
		return fmt.Errorf("name %q is not a cookie token", c.Name)
	}
	if len(c.Value) > maxUnlockCookieValue {
		return fmt.Errorf("value is over %d bytes", maxUnlockCookieValue)
	}
	if strings.ContainsAny(c.Value, ";,\" \\") || strings.ContainsFunc(c.Value, unicode.IsControl) {
		return fmt.Errorf("value holds a character a cookie cannot carry (control, space, quote, comma, semicolon or backslash)")
	}
	if c.Path != "" && (!strings.HasPrefix(c.Path, "/") || strings.ContainsAny(c.Path, ";") || strings.ContainsFunc(c.Path, unicode.IsControl)) {
		return fmt.Errorf("path %q must start with / and hold no ';' or control character", c.Path)
	}
	return nil
}

// validateStub checks one stub and rewrites an absolute-URL path on the
// origin to its path, so matching sees one form.
func (p *UnlockProfile) validateStub(s *UnlockStub, origin *url.URL) error {
	s.Method = strings.ToUpper(strings.TrimSpace(s.Method))
	if !isHTTPToken(s.Method) {
		return fmt.Errorf("method %q is not an HTTP method token", s.Method)
	}
	if strings.Contains(s.Path, "://") {
		u, err := url.Parse(s.Path)
		if err != nil {
			return fmt.Errorf("path %q is not a URL: %w", s.Path, err)
		}
		if !sameUnlockOrigin(origin, u) || u.User != nil {
			return fmt.Errorf("%s is not on the profile origin %s: a stub may only answer the app's own origin", s.Path, origin)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("path %q carries a query or fragment; stubs match the path only", s.Path)
		}
		s.Path = cmp.Or(u.EscapedPath(), "/")
	}
	if !strings.HasPrefix(s.Path, "/") || strings.HasPrefix(s.Path, "//") {
		return fmt.Errorf("path %q must be a path on the origin (starting with a single /) or an absolute URL on it", s.Path)
	}
	if strings.ContainsAny(s.Path, "?#") || strings.ContainsFunc(s.Path, unicode.IsControl) {
		return fmt.Errorf("path %q carries a query, fragment or control character; stubs match the path only", s.Path)
	}
	// 1xx cannot be fulfilled, and a 3xx would send the page on to a real
	// request whose provenance the stub then shares.
	if (s.Status < 200 || s.Status > 299) && (s.Status < 400 || s.Status > 599) {
		return fmt.Errorf("status %d must be 2xx, 4xx or 5xx", s.Status)
	}
	if len(s.ContentType) > maxUnlockContentTypeLn || strings.ContainsFunc(s.ContentType, unicode.IsControl) {
		return fmt.Errorf("contentType must be at most %d bytes with no control character", maxUnlockContentTypeLn)
	}
	if len(s.Body) > MaxUnlockStubBody {
		return fmt.Errorf("body is %d bytes, over the %d-byte limit", len(s.Body), MaxUnlockStubBody)
	}
	return nil
}

// isHTTPToken reports whether s is an RFC 9110 token (the grammar of a method
// and a cookie name).
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte("\"(),/:;<=>?@[\\]{}", c) >= 0 {
			return false
		}
	}
	return true
}

// matchStub returns the index of the first stub answering method on u, or
// -1. Only a URL on origin can match.
func (p *UnlockProfile) matchStub(origin *url.URL, method string, u *url.URL) int {
	if u == nil || !sameUnlockOrigin(origin, u) {
		return -1
	}
	path := cmp.Or(u.EscapedPath(), "/")
	method = strings.ToUpper(method)
	for i, s := range p.Stubs {
		if s.Method == method && stubPathMatches(s.Path, path) {
			return i
		}
	}
	return -1
}

// stubPathMatches compares a stub path to a request path segment by segment.
// A ":name" or "{name}" segment matches any one non-empty segment; every
// other segment matches exactly.
func stubPathMatches(pattern, path string) bool {
	if pattern == path {
		return true
	}
	for {
		pseg, prest, pmore := strings.Cut(pattern, "/")
		rseg, rrest, rmore := strings.Cut(path, "/")
		if isStubParam(pseg) {
			if rseg == "" {
				return false
			}
		} else if pseg != rseg {
			return false
		}
		if pmore != rmore {
			return false // different segment counts
		}
		if !pmore {
			return true
		}
		pattern, path = prest, rrest
	}
}

func isStubParam(seg string) bool {
	if len(seg) > 1 && seg[0] == ':' {
		return true
	}
	return len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}'
}

// safeUnlockMethod reports whether a request with method is let through a
// walk without a write grant: GET, HEAD and OPTIONS change no state.
func safeUnlockMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}
