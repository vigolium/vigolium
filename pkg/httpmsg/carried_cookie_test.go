package httpmsg

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

var cookieNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestCookieHeaderFor is the table WP9 exists for: a flat Cookie header cannot
// express Domain, Path, Secure or Expires, so every harvested cookie used to be
// attached to every request to the host. Each row here is a cookie a browser
// would NOT have sent.
func TestCookieHeaderFor(t *testing.T) {
	hostOnly := CarriedCookie{Name: "ho", Value: "1", Domain: "app.test", Path: "/", HostOnly: true}
	domainWide := CarriedCookie{Name: "dw", Value: "2", Domain: "app.test", Path: "/"}
	adminScoped := CarriedCookie{Name: "adm", Value: "3", Domain: "app.test", Path: "/admin"}
	rootScoped := CarriedCookie{Name: "adm", Value: "root", Domain: "app.test", Path: "/"}
	secureOnly := CarriedCookie{Name: "sec", Value: "4", Domain: "app.test", Path: "/", Secure: true}
	expired := CarriedCookie{Name: "old", Value: "5", Domain: "app.test", Path: "/", Expires: cookieNow.Add(-time.Hour)}
	future := CarriedCookie{Name: "new", Value: "6", Domain: "app.test", Path: "/", Expires: cookieNow.Add(time.Hour)}

	for _, tc := range []struct {
		name    string
		cookies []CarriedCookie
		url     string
		want    string
	}{
		{
			name:    "host-only cookie on the exact host",
			cookies: []CarriedCookie{hostOnly},
			url:     "https://app.test/",
			want:    "ho=1",
		},
		{
			name:    "host-only cookie NOT on a subdomain",
			cookies: []CarriedCookie{hostOnly},
			url:     "https://api.app.test/",
			want:    "",
		},
		{
			name:    "domain cookie reaches a subdomain",
			cookies: []CarriedCookie{domainWide},
			url:     "https://api.app.test/",
			want:    "dw=2",
		},
		{
			name:    "/admin cookie on /admin",
			cookies: []CarriedCookie{adminScoped},
			url:     "https://app.test/admin",
			want:    "adm=3",
		},
		{
			name:    "/admin cookie on /admin/users",
			cookies: []CarriedCookie{adminScoped},
			url:     "https://app.test/admin/users",
			want:    "adm=3",
		},
		{
			name:    "/admin cookie NOT on /administrator",
			cookies: []CarriedCookie{adminScoped},
			url:     "https://app.test/administrator",
			want:    "",
		},
		{
			name:    "/admin cookie NOT on /",
			cookies: []CarriedCookie{adminScoped},
			url:     "https://app.test/",
			want:    "",
		},
		{
			name:    "Secure cookie over https",
			cookies: []CarriedCookie{secureOnly},
			url:     "https://app.test/",
			want:    "sec=4",
		},
		{
			name:    "Secure cookie NOT over http",
			cookies: []CarriedCookie{secureOnly},
			url:     "http://app.test/",
			want:    "",
		},
		{
			name:    "expired cookie dropped, session cookie kept",
			cookies: []CarriedCookie{expired, hostOnly, future},
			url:     "https://app.test/",
			want:    "ho=1; new=6",
		},
		{
			name:    "duplicate name: the most specific path wins on a matching path",
			cookies: []CarriedCookie{rootScoped, adminScoped},
			url:     "https://app.test/admin/x",
			want:    "adm=3",
		},
		{
			name:    "duplicate name: only the root copy matches elsewhere",
			cookies: []CarriedCookie{rootScoped, adminScoped},
			url:     "https://app.test/public",
			want:    "adm=root",
		},
		{
			name:    "longer paths first, per RFC 6265 §5.4",
			cookies: []CarriedCookie{domainWide, adminScoped},
			url:     "https://app.test/admin",
			want:    "adm=3; dw=2",
		},
		{
			name:    "an empty request path is /",
			cookies: []CarriedCookie{domainWide},
			url:     "https://app.test",
			want:    "dw=2",
		},
		{
			name:    "a cookie for another domain never applies",
			cookies: []CarriedCookie{{Name: "x", Value: "1", Domain: "other.test", Path: "/"}},
			url:     "https://app.test/",
			want:    "",
		},
		{
			name:    "a port on the request host does not matter",
			cookies: []CarriedCookie{hostOnly},
			url:     "https://app.test:8443/",
			want:    "ho=1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := CarriedSession{Cookies: tc.cookies}
			if got := sess.CookieHeaderFor(mustParseURL(t, tc.url), cookieNow); got != tc.want {
				t.Errorf("CookieHeaderFor(%s) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

// A harvest from before attributes were recorded carries only the flat header,
// and must keep behaving exactly as it did.
func TestCookieHeaderFor_FallsBackToFlatHeader(t *testing.T) {
	sess := CarriedSession{CookieHeader: "cf_clearance=abc; sess=1"}
	got := sess.CookieHeaderFor(mustParseURL(t, "http://app.test/anything"), cookieNow)
	if got != "cf_clearance=abc; sess=1" {
		t.Errorf("CookieHeaderFor = %q, want the flat fallback", got)
	}
	// Even for a host the session was not harvested from: the caller keys these
	// by host, so this function is not the host gate.
	if got := sess.CookieHeaderFor(mustParseURL(t, "http://other.test/"), cookieNow); got == "" {
		t.Error("the flat fallback must not be host-filtered here; the map lookup does that")
	}
}

// A nil URL yields nothing rather than panicking, and an empty session yields
// nothing.
func TestCookieHeaderFor_Degenerate(t *testing.T) {
	withCookies := CarriedSession{Cookies: []CarriedCookie{{Name: "a", Value: "1", Domain: "app.test", Path: "/"}}}
	if got := withCookies.CookieHeaderFor(nil, cookieNow); got != "" {
		t.Errorf("nil URL = %q, want empty", got)
	}
	if got := withCookies.CookieHeaderFor(mustParseURL(t, "https:///path"), cookieNow); got != "" {
		t.Errorf("hostless URL = %q, want empty", got)
	}
	if got := (CarriedSession{}).CookieHeaderFor(mustParseURL(t, "https://app.test/"), cookieNow); got != "" {
		t.Errorf("empty session = %q, want empty", got)
	}
}

// TestCookieHeaderForOrigin: the content-discovery engine takes one static
// Cookie header per target, so there is no request path to match — but the
// scheme is known, and a Secure cookie must not ride a plain-http crawl.
func TestCookieHeaderForOrigin(t *testing.T) {
	cookies := []CarriedCookie{
		{Name: "ho", Value: "1", Domain: "app.test", Path: "/", HostOnly: true},
		{Name: "adm", Value: "3", Domain: "app.test", Path: "/admin"},
		{Name: "sec", Value: "4", Domain: "app.test", Path: "/", Secure: true},
		{Name: "old", Value: "5", Domain: "app.test", Path: "/", Expires: cookieNow.Add(-time.Minute)},
	}
	sess := CarriedSession{Cookies: cookies}

	// https: everything unexpired, path ignored, broadest first.
	if got := sess.CookieHeaderForOrigin("https", "app.test", cookieNow); got != "ho=1; sec=4; adm=3" {
		t.Errorf("https origin = %q", got)
	}
	// http: the Secure cookie is gone. This is the WP's headline Deparos fix.
	if got := sess.CookieHeaderForOrigin("http", "app.test", cookieNow); got != "ho=1; adm=3" {
		t.Errorf("http origin = %q, want the Secure cookie dropped", got)
	}
	// Host-only cookies do not reach a subdomain target.
	if got := sess.CookieHeaderForOrigin("https", "api.app.test", cookieNow); got != "sec=4; adm=3" {
		t.Errorf("subdomain origin = %q, want only the domain cookies", got)
	}
	// Unknown host → nothing.
	if got := sess.CookieHeaderForOrigin("https", "other.test", cookieNow); got != "" {
		t.Errorf("unrelated origin = %q, want empty", got)
	}
	// With no path to match, a duplicated name keeps the BROADEST copy.
	dup := CarriedSession{Cookies: []CarriedCookie{
		{Name: "adm", Value: "narrow", Domain: "app.test", Path: "/admin"},
		{Name: "adm", Value: "broad", Domain: "app.test", Path: "/"},
	}}
	if got := dup.CookieHeaderForOrigin("https", "app.test", cookieNow); got != "adm=broad" {
		t.Errorf("duplicate name = %q, want the broadest path", got)
	}
	// And the flat fallback for an attribute-free harvest.
	flat := CarriedSession{CookieHeader: "a=1"}
	if got := flat.CookieHeaderForOrigin("http", "app.test", cookieNow); got != "a=1" {
		t.Errorf("flat fallback = %q", got)
	}
}

// TestCarriedCookiesFromHTTP recovers the host-only bit from the Domain
// attribute: CDP reports host-only cookies with a bare domain and domain
// cookies with a leading dot.
func TestCarriedCookiesFromHTTP(t *testing.T) {
	in := []*http.Cookie{
		{Name: "ho", Value: "1", Domain: "app.test", Path: "/"},
		{Name: "dw", Value: "2", Domain: ".app.test", Path: "/"},
		{Name: "nodomain", Value: "3"},
		{Name: "pathless", Value: "4", Domain: "app.test"},
		{Name: "other", Value: "5", Domain: "unrelated.test", Path: "/"},
		{Name: "expired", Value: "6", Domain: "app.test", Path: "/", Expires: time.Now().Add(-time.Hour)},
		{Name: "", Value: "7", Domain: "app.test"},
		nil,
	}

	got := CarriedCookiesFromHTTP("App.Test:8443", in)
	byName := make(map[string]CarriedCookie, len(got))
	for _, c := range got {
		byName[c.Name] = c
	}

	if len(got) != 4 {
		t.Fatalf("got %d cookies (%v), want 4", len(got), byName)
	}
	if c := byName["ho"]; !c.HostOnly || c.Domain != "app.test" {
		t.Errorf("ho = %+v, want host-only on app.test", c)
	}
	if c := byName["dw"]; c.HostOnly || c.Domain != "app.test" {
		t.Errorf("dw = %+v, want domain-wide with the dot stripped", c)
	}
	if c := byName["nodomain"]; !c.HostOnly || c.Domain != "app.test" {
		t.Errorf("nodomain = %+v, want host-only on the session host", c)
	}
	if c := byName["pathless"]; c.Path != "/" {
		t.Errorf("pathless Path = %q, want /", c.Path)
	}
	for _, dropped := range []string{"other", "expired", ""} {
		if _, ok := byName[dropped]; ok {
			t.Errorf("cookie %q should have been dropped", dropped)
		}
	}

	if CarriedCookiesFromHTTP("", in) != nil {
		t.Error("an empty host must yield nothing")
	}
	if CarriedCookiesFromHTTP("app.test", nil) != nil {
		t.Error("no cookies must yield nothing")
	}
	if CarriedCookiesFromHTTP("app.test", []*http.Cookie{{Name: "x", Domain: "other.test"}}) != nil {
		t.Error("nothing applicable must yield nil, not an empty slice")
	}
}

// Round trip: a harvested jar converted and then evaluated for the host it was
// harvested from sends what the browser would.
func TestCarriedCookiesFromHTTP_RoundTrip(t *testing.T) {
	jar := []*http.Cookie{
		{Name: "sid", Value: "s", Domain: "app.test", Path: "/"},
		{Name: "admin_csrf", Value: "c", Domain: "app.test", Path: "/admin"},
		{Name: "tracker", Value: "t", Domain: ".app.test", Path: "/", Secure: true},
	}
	sess := CarriedSession{
		CookieHeader: FlattenCookiesForHost("app.test", jar),
		Cookies:      CarriedCookiesFromHTTP("app.test", jar),
	}

	if got := sess.CookieHeaderFor(mustParseURL(t, "https://app.test/admin/panel"), cookieNow); got != "admin_csrf=c; sid=s; tracker=t" {
		t.Errorf("/admin/panel over https = %q", got)
	}
	if got := sess.CookieHeaderFor(mustParseURL(t, "http://app.test/index"), cookieNow); got != "sid=s" {
		t.Errorf("/index over http = %q, want only the site-wide non-Secure cookie", got)
	}
	// The flat header, for contrast, is everything — which is what used to be
	// attached to every request.
	if sess.CookieHeader != "sid=s; tracker=t; admin_csrf=c" {
		t.Errorf("flat header = %q", sess.CookieHeader)
	}
}

// TestFlattenCookiesForHost_SkipsExpiredAndPrefersBroadestPath extends the
// existing flatten tests with the two behaviours WP9 adds to it. A flat header
// is one static value for a whole host, so an expired cookie is pure noise and
// the broadest copy of a duplicated name is the one most likely to apply.
func TestFlattenCookiesForHost_SkipsExpiredAndPrefersBroadestPath(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "dup", Value: "narrow", Domain: "app.test", Path: "/admin/deep"},
		{Name: "dup", Value: "broad", Domain: "app.test", Path: "/"},
		{Name: "gone", Value: "x", Domain: "app.test", Path: "/", Expires: time.Now().Add(-time.Minute)},
		{Name: "kept", Value: "y", Domain: "app.test", Path: "/", Expires: time.Now().Add(time.Hour)},
		{Name: "session", Value: "z", Domain: "app.test"},
	}
	// Broadest paths first, then harvest order; an unset path ranks with "/".
	got := FlattenCookiesForHost("app.test", cookies)
	want := "dup=broad; kept=y; session=z"
	if got != want {
		t.Errorf("FlattenCookiesForHost = %q, want %q", got, want)
	}
	// Everything expired → nothing, not an empty-but-present header.
	onlyExpired := []*http.Cookie{{Name: "gone", Value: "x", Domain: "app.test", Expires: time.Now().Add(-time.Minute)}}
	if got := FlattenCookiesForHost("app.test", onlyExpired); got != "" {
		t.Errorf("all-expired = %q, want empty", got)
	}
}

func TestOverrideCookieHeaders(t *testing.T) {
	cases := []struct{ existing, override, want string }{
		{"session=s1; TrackingId=orig", "TrackingId=P", "session=s1; TrackingId=P"},
		{"session=s1; trackingid=orig", "TrackingId=P", "session=s1; TrackingId=P"},
		{"session=s1", "a=1; b=2", "session=s1; a=1; b=2"},
		{"", "a=1", "a=1"},
		{" a=1 ;; b=2 ", "", "a=1; b=2"},
	}
	for _, tc := range cases {
		if got := OverrideCookieHeaders(tc.existing, tc.override); got != tc.want {
			t.Errorf("OverrideCookieHeaders(%q, %q) = %q, want %q", tc.existing, tc.override, got, tc.want)
		}
	}
}
