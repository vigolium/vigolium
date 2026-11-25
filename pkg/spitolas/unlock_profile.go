package spitolas

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"golang.org/x/net/http/httpguts"
)

// UnlockProfile is the client state an unlock walk forges before it visits a
// single-page app's routes: storage seeds, cookies, response stubs for the
// app's own bootstrap and permission calls, and rewrites of real answers. The
// caller (a model reading the app's bundle) decides how the app's client-side
// gate works and writes the profile; UnlockWalk only applies it.
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
	// Rewrites change the real answer of matching same-origin requests: the
	// request reaches the target, and the page receives its response with a
	// status and/or JSON fields changed. A rewritten exchange is never stored;
	// the walk reports it as a rewrite, never as traffic. A request a stub
	// matches is stubbed, not rewritten.
	Rewrites []UnlockRewrite `json:"rewrites,omitempty"`
	// Routes are visited in order after Origin's root, each a path (or
	// absolute URL) on Origin, taken verbatim.
	Routes []string `json:"routes,omitempty"`
	// MaxRoutes caps how many Routes are visited (default 40, at most 200).
	MaxRoutes int `json:"maxRoutes,omitempty"`
	// SettleMs bounds the wait for the network to go idle after each
	// navigation (default 2500, at most 10000).
	SettleMs int `json:"settleMs,omitempty"`
	// MaxClicksPerRoute caps the controls the walk clicks on each rendered
	// route (default 6, at most 30; 0 turns clicking off). Clicking is refused
	// whatever this says when the walk lets writes through.
	MaxClicksPerRoute *int `json:"maxClicksPerRoute,omitempty"`
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

// UnlockRewrite changes one real answer. Method and Path match like a stub's.
// Status replaces the upstream status (2xx, 4xx or 5xx; 0 keeps it); each Set
// entry sets one member of the upstream JSON body. A rewrite needs at least one
// of the two, and applies all of them or none: an answer it cannot change (not
// JSON, a pointer that does not resolve, a body over the limit) reaches the page
// unchanged and the walk reports why.
type UnlockRewrite struct {
	Method string             `json:"method"`
	Path   string             `json:"path"`
	Status int                `json:"status,omitempty"`
	Set    []UnlockRewriteSet `json:"set,omitempty"`
}

// UnlockRewriteSet sets the member Pointer (an RFC 6901 JSON pointer, never
// the whole document) to Value. An object member is replaced or added; an
// array element is replaced, and "-" (or the array's length) appends. Every
// container above the member must exist.
type UnlockRewriteSet struct {
	Pointer string          `json:"pointer"`
	Value   json.RawMessage `json:"value"`
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

	maxUnlockRewrites    = 100
	maxUnlockRewriteSets = 20
	maxUnlockPointerLen  = 512
	// MaxUnlockRewriteValues bounds the values one rewrite sets, together.
	MaxUnlockRewriteValues = 64 << 10
	// MaxUnlockRewriteUpstream bounds the upstream body a rewrite decodes; a
	// larger answer reaches the page unchanged.
	MaxUnlockRewriteUpstream = 4 << 20

	DefaultUnlockClicksPerRoute = 6
	MaxUnlockClicksPerRoute     = 30
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
	if p.MaxClicksPerRoute == nil {
		n := DefaultUnlockClicksPerRoute
		p.MaxClicksPerRoute = &n
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
	if c := p.MaxClicksPerRoute; c != nil && (*c < 0 || *c > MaxUnlockClicksPerRoute) {
		return profileErr("maxClicksPerRoute %d is outside 0..%d", *c, MaxUnlockClicksPerRoute)
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
	if len(p.Rewrites) > maxUnlockRewrites {
		return profileErr("%d rewrites, over the limit of %d", len(p.Rewrites), maxUnlockRewrites)
	}
	for i := range p.Rewrites {
		if err := p.validateRewrite(&p.Rewrites[i], origin); err != nil {
			return profileErr("rewrites[%d]: %v", i, err)
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
	method, path, err := validateUnlockMatch(s.Method, s.Path, origin, "a stub may only answer the app's own origin")
	if err != nil {
		return err
	}
	s.Method, s.Path = method, path
	if !answerableUnlockStatus(s.Status) {
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

// validateUnlockMatch checks a stub's or rewrite's method and path and returns
// them normalised: the method upper-cased, an absolute URL on the origin
// reduced to its path. offOrigin ends the refusal of a URL on another origin.
func validateUnlockMatch(method, path string, origin *url.URL, offOrigin string) (string, string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if !isHTTPToken(method) {
		return "", "", fmt.Errorf("method %q is not an HTTP method token", method)
	}
	if strings.Contains(path, "://") {
		u, err := url.Parse(path)
		if err != nil {
			return "", "", fmt.Errorf("path %q is not a URL: %w", path, err)
		}
		if !sameUnlockOrigin(origin, u) || u.User != nil {
			return "", "", fmt.Errorf("%s is not on the profile origin %s: %s", path, origin, offOrigin)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return "", "", fmt.Errorf("path %q carries a query or fragment; matching sees the path only", path)
		}
		path = cmp.Or(u.EscapedPath(), "/")
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "", "", fmt.Errorf("path %q must be a path on the origin (starting with a single /) or an absolute URL on it", path)
	}
	if strings.ContainsAny(path, "?#") || strings.ContainsFunc(path, unicode.IsControl) {
		return "", "", fmt.Errorf("path %q carries a query, fragment or control character; matching sees the path only", path)
	}
	return method, path, nil
}

// answerableUnlockStatus reports whether a forged or rewritten answer may
// carry status: 1xx cannot be fulfilled, and a 3xx would send the page on to a
// real request whose provenance the forged answer then shares.
func answerableUnlockStatus(status int) bool {
	return (status >= 200 && status <= 299) || (status >= 400 && status <= 599)
}

// validateRewrite checks one rewrite: the match as a stub's, a status a
// forged answer may carry, and bounded, well-formed pointers and values. A
// rewrite whose method and path a stub already answers is refused: the stub
// would answer every request it matches and the rewrite would never run.
func (p *UnlockProfile) validateRewrite(r *UnlockRewrite, origin *url.URL) error {
	method, path, err := validateUnlockMatch(r.Method, r.Path, origin, "a rewrite may only change the app's own answers")
	if err != nil {
		return err
	}
	r.Method, r.Path = method, path
	for i, s := range p.Stubs {
		if s.Method == r.Method && s.Path == r.Path {
			return fmt.Errorf("stubs[%d] already answers %s %s; a rewrite of it would never run", i, s.Method, s.Path)
		}
	}
	if r.Status != 0 && !answerableUnlockStatus(r.Status) {
		return fmt.Errorf("status %d must be 2xx, 4xx or 5xx (or absent to keep the upstream status)", r.Status)
	}
	if r.Status == 0 && len(r.Set) == 0 {
		return errors.New("changes nothing: give a status, a set, or both")
	}
	if len(r.Set) > maxUnlockRewriteSets {
		return fmt.Errorf("%d set entries, over the limit of %d", len(r.Set), maxUnlockRewriteSets)
	}
	total := 0
	for i, s := range r.Set {
		if _, err := parseJSONPointer(s.Pointer); err != nil {
			return fmt.Errorf("set[%d]: %w", i, err)
		}
		if len(s.Value) == 0 {
			return fmt.Errorf("set[%d]: value is required (JSON; null sets null)", i)
		}
		if !json.Valid(s.Value) {
			return fmt.Errorf("set[%d]: value is not valid JSON", i)
		}
		total += len(s.Value)
	}
	if total > MaxUnlockRewriteValues {
		return fmt.Errorf("values total %d bytes, over the %d-byte limit", total, MaxUnlockRewriteValues)
	}
	return nil
}

// parseJSONPointer splits an RFC 6901 pointer into its unescaped reference
// tokens. The empty pointer (the whole document) is refused: replacing a whole
// answer is a stub, not a rewrite.
func parseJSONPointer(ptr string) ([]string, error) {
	if ptr == "" {
		return nil, errors.New(`pointer "" names the whole answer; a rewrite changes members (use a stub to replace an answer)`)
	}
	if len(ptr) > maxUnlockPointerLen {
		return nil, fmt.Errorf("pointer is over %d bytes", maxUnlockPointerLen)
	}
	if ptr[0] != '/' || !utf8.ValidString(ptr) || strings.ContainsFunc(ptr, unicode.IsControl) {
		return nil, fmt.Errorf("pointer %q must start with / (RFC 6901) and hold no control character", ptr)
	}
	tokens := strings.Split(ptr[1:], "/")
	for i, t := range tokens {
		for j := 0; j < len(t); j++ {
			if t[j] == '~' && (j+1 >= len(t) || (t[j+1] != '0' && t[j+1] != '1')) {
				return nil, fmt.Errorf("pointer %q has a ~ that is not ~0 or ~1", ptr)
			}
		}
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}

// apply changes one upstream answer: the status when the rewrite names one,
// and each Set member of the JSON body, in order. It changes all or nothing.
func (r *UnlockRewrite) apply(upstreamStatus int, body []byte) (int, []byte, error) {
	status := cmp.Or(r.Status, upstreamStatus)
	if len(r.Set) == 0 {
		return status, body, nil
	}
	if len(body) > MaxUnlockRewriteUpstream {
		return 0, nil, fmt.Errorf("the upstream body is %d bytes, over the %d-byte limit", len(body), MaxUnlockRewriteUpstream)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return 0, nil, fmt.Errorf("the upstream body is not JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return 0, nil, errors.New("the upstream body is not one JSON document")
	}
	for i, s := range r.Set {
		tokens, err := parseJSONPointer(s.Pointer)
		if err != nil {
			return 0, nil, fmt.Errorf("set[%d]: %w", i, err)
		}
		vdec := json.NewDecoder(bytes.NewReader(s.Value))
		vdec.UseNumber()
		var v any
		if err := vdec.Decode(&v); err != nil {
			return 0, nil, fmt.Errorf("set[%d]: value: %w", i, err)
		}
		if doc, err = setJSONPointer(doc, tokens, v); err != nil {
			return 0, nil, fmt.Errorf("set[%d] %s: %w", i, s.Pointer, err)
		}
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return 0, nil, err
	}
	return status, bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// setJSONPointer sets the member tokens name in doc to v and returns the
// changed document. Every container above the member must exist.
func setJSONPointer(doc any, tokens []string, v any) (any, error) {
	if len(tokens) == 0 {
		return v, nil
	}
	tok, rest := tokens[0], tokens[1:]
	switch c := doc.(type) {
	case map[string]any:
		if len(rest) == 0 {
			c[tok] = v
			return c, nil
		}
		child, ok := c[tok]
		if !ok {
			return nil, fmt.Errorf("member %q does not exist", tok)
		}
		nv, err := setJSONPointer(child, rest, v)
		if err != nil {
			return nil, err
		}
		c[tok] = nv
		return c, nil
	case []any:
		if tok == "-" || tok == strconv.Itoa(len(c)) {
			if len(rest) != 0 {
				return nil, fmt.Errorf("index %q is past the end of the array", tok)
			}
			return append(c, v), nil
		}
		idx, err := strconv.Atoi(tok)
		if err != nil || idx < 0 || idx >= len(c) || (len(tok) > 1 && tok[0] == '0') {
			return nil, fmt.Errorf("index %q is not an element of an array of %d", tok, len(c))
		}
		nv, err := setJSONPointer(c[idx], rest, v)
		if err != nil {
			return nil, err
		}
		c[idx] = nv
		return c, nil
	}
	return nil, fmt.Errorf("%q is below a value that is not an object or an array", tok)
}

// isHTTPToken reports whether s is an RFC 9110 token (the grammar of a method
// and a cookie name).
func isHTTPToken(s string) bool {
	return httpguts.ValidHeaderFieldName(s)
}

// matchStub returns the index of the first stub answering method on u, or
// -1. Only a URL on origin can match.
func (p *UnlockProfile) matchStub(origin *url.URL, method string, u *url.URL) int {
	return matchUnlock(origin, method, u, p.Stubs, func(s UnlockStub) (string, string) { return s.Method, s.Path })
}

// matchRewrite returns the index of the first rewrite matching method on u,
// or -1. Only a URL on origin can match.
func (p *UnlockProfile) matchRewrite(origin *url.URL, method string, u *url.URL) int {
	return matchUnlock(origin, method, u, p.Rewrites, func(r UnlockRewrite) (string, string) { return r.Method, r.Path })
}

// matchUnlock is the one matcher stubs and rewrites share: the first entry
// whose method and path pattern answer method on u, or -1.
func matchUnlock[T any](origin *url.URL, method string, u *url.URL, entries []T, key func(T) (method, path string)) int {
	if u == nil || !sameUnlockOrigin(origin, u) {
		return -1
	}
	path := cmp.Or(u.EscapedPath(), "/")
	method = strings.ToUpper(method)
	for i, e := range entries {
		if m, pat := key(e); m == method && stubPathMatches(pat, path) {
			return i
		}
	}
	return -1
}

// forgedAnswer reports whether the walk forged the answer to method on u: a
// stub answered it or a rewrite changed it. Such an exchange is never stored.
func (p *UnlockProfile) forgedAnswer(origin *url.URL, method string, u *url.URL) bool {
	return p.matchStub(origin, method, u) >= 0 || p.matchRewrite(origin, method, u) >= 0
}

// rewriteFetchPatterns are the Fetch URL patterns that pause the rewrites'
// responses: each path on the origin with its parameter segments as "*", and
// a trailing "*" for the query string. A pattern may pause more than the
// rewrite matches; the walk's own matcher decides.
func (p *UnlockProfile) rewriteFetchPatterns(origin *url.URL) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range p.Rewrites {
		segs := strings.Split(r.Path, "/")
		for i, seg := range segs {
			if isStubParam(seg) {
				segs[i] = "*"
				continue
			}
			// Fetch patterns treat * and ? as wildcards and \ as their escape.
			segs[i] = strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?").Replace(seg)
		}
		pat := origin.String() + strings.Join(segs, "/") + "*"
		if !seen[pat] {
			seen[pat] = true
			out = append(out, pat)
		}
	}
	return out
}

// ClicksPerRoute is the profile's click cap with the default filled in.
func (p *UnlockProfile) ClicksPerRoute() int {
	if p.MaxClicksPerRoute == nil {
		return DefaultUnlockClicksPerRoute
	}
	return *p.MaxClicksPerRoute
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
