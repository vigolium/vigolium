package harvester

import (
	"strconv"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string
		reason dropReason
	}{
		{"lowercase scheme and host", "HTTPS://WWW.Example.COM/Path/A", "https://www.example.com/Path/A", dropNone},
		{"drop https default port", "https://example.com:443/a", "https://example.com/a", dropNone},
		{"drop http default port", "http://example.com:80/a", "http://example.com/a", dropNone},
		{"keep non-default port", "https://example.com:8443/a", "https://example.com:8443/a", dropNone},
		{"cross default port kept", "http://example.com:443/a", "http://example.com:443/a", dropNone},
		{"drop fragment", "https://example.com/a#section", "https://example.com/a", dropNone},
		{"empty path becomes root", "https://example.com", "https://example.com/", dropNone},
		{"sort query keys", "https://example.com/s?q=1&a=2&m=3", "https://example.com/s?a=2&m=3&q=1", dropNone},
		{"stable for repeated keys", "https://example.com/s?b=2&a=x&b=1", "https://example.com/s?a=x&b=2&b=1", dropNone},
		{"value encoding preserved", "https://example.com/s?z=a%2Fb&a=c+d", "https://example.com/s?a=c+d&z=a%2Fb", dropNone},
		{"drop utm params", "https://example.com/p?utm_source=x&id=3&UTM_Medium=y", "https://example.com/p?id=3", dropNone},
		{"drop click ids", "https://example.com/p?fbclid=1&gclid=2&_ga=3&mc_cid=4&mc_eid=5&msclkid=6", "https://example.com/p", dropNone},
		{"drop empty pairs", "https://example.com/p?&a=1&&", "https://example.com/p?a=1", dropNone},
		{"bare question mark dropped", "https://example.com/p?", "https://example.com/p", dropNone},
		{"ipv6 host", "http://[::1]:80/x", "http://[::1]/x", dropNone},
		{"js kept", "https://example.com/static/app.min.js", "https://example.com/static/app.min.js", dropNone},
		{"source map kept", "https://example.com/static/app.js.map", "https://example.com/static/app.js.map", dropNone},
		{"gzipped sitemap kept", "https://example.com/sitemap.xml.gz", "https://example.com/sitemap.xml.gz", dropNone},
		{"image dropped", "https://example.com/logo.PNG", "", dropStatic},
		{"image with query dropped", "https://example.com/logo.png?v=3", "", dropStatic},
		{"font dropped", "https://example.com/f/a.woff2", "", dropStatic},
		{"css dropped", "https://example.com/site.css", "", dropStatic},
		{"video dropped", "https://example.com/intro.mp4", "", dropStatic},
		{"archive kept for an existence check", "https://example.com/dl/release.tar.gz", "https://example.com/dl/release.tar.gz", dropNone},
		{"zip kept for an existence check", "https://example.com/dl/release.zip", "https://example.com/dl/release.zip", dropNone},
		{"empty", "  ", "", dropInvalid},
		{"relative", "/just/a/path", "", dropInvalid},
		{"non-http scheme", "ftp://example.com/file", "", dropInvalid},
		{"unparseable", "http://exa mple.com/%zz", "", dropInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, reason := normalizeURL(tt.in)
			if reason != tt.reason {
				t.Fatalf("reason = %q, want %q", reason, tt.reason)
			}
			if tt.reason != dropNone {
				return
			}
			if got := u.String(); got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestShapeKey(t *testing.T) {
	shape := func(raw string) string {
		t.Helper()
		u, reason := normalizeURL(raw)
		if reason != dropNone {
			t.Fatalf("normalizeURL(%q) dropped: %s", raw, reason)
		}
		return shapeKey(u)
	}

	same := [][2]string{
		{"https://example.com/users/42/orders", "https://example.com/users/7/orders"},
		{"http://example.com/users/42", "https://example.com/users/43"}, // scheme ignored
		{"https://example.com/item?id=1&lang=en", "https://example.com/item?lang=fr&id=2"},
		{"https://example.com/item?id=1&id=2", "https://example.com/item?id=3"}, // names are unique
		{"https://example.com/o/550e8400-e29b-41d4-a716-446655440000", "https://example.com/o/9b2f7c1e-0000-4000-8000-000000000000"},
	}
	for _, p := range same {
		if a, b := shape(p[0]), shape(p[1]); a != b {
			t.Errorf("want same shape:\n  %s -> %s\n  %s -> %s", p[0], a, p[1], b)
		}
	}

	different := [][2]string{
		{"https://example.com/about-us", "https://example.com/contact"},              // slugs stay literal
		{"https://example.com/item?id=1", "https://example.com/item?sku=1"},          // query names differ
		{"https://example.com/item", "https://example.com/item?id=1"},                // query present vs not
		{"https://a.example.com/users/1", "https://b.example.com/users/1"},           // host differs
		{"https://example.com:8443/users/1", "https://example.com/users/1"},          // port differs
		{"https://example.com/api/v1/users/1", "https://example.com/api/v2/users/1"}, // versions literal
	}
	for _, p := range different {
		if a, b := shape(p[0]), shape(p[1]); a == b {
			t.Errorf("want different shapes, both %q: %s vs %s", a, p[0], p[1])
		}
	}
}

func TestShaperAdmit(t *testing.T) {
	s := newShaper(Options{PerShape: 2, MaxURLs: 3})

	inputs := []string{
		"https://example.com/users/1",         // kept (shape A 1/2)
		"https://EXAMPLE.com:443/users/1#x",   // duplicate after normalization
		"https://example.com/users/2?utm_x=1", // kept (shape A 2/2)
		"https://example.com/users/3",         // over per-shape
		"https://example.com/logo.png",        // static
		"not a url",                           // invalid
		"https://example.com/about",           // kept (domain 3/3)
		"https://example.com/contact",         // over domain cap
	}
	var kept []string
	for _, in := range inputs {
		if u, ok := s.admit("example.com", in); ok {
			kept = append(kept, u)
		}
	}

	want := []string{"https://example.com/users/1", "https://example.com/users/2", "https://example.com/about"}
	if len(kept) != len(want) {
		t.Fatalf("kept = %v, want %v", kept, want)
	}
	for i := range want {
		if kept[i] != want[i] {
			t.Errorf("kept[%d] = %q, want %q", i, kept[i], want[i])
		}
	}

	st := s.stats
	if st.Raw != 8 || st.Kept != 3 || st.Duplicate != 1 || st.OverShape != 1 ||
		st.Static != 1 || st.Invalid != 1 || st.OverDomainCap != 1 {
		t.Errorf("stats = %+v", st)
	}
	if sum := st.Invalid + st.Static + st.Duplicate + st.OverShape + st.OverDomainCap + st.Kept; sum != st.Raw {
		t.Errorf("drop reasons (%d) do not add up to raw (%d)", sum, st.Raw)
	}

	// The domain cap is per domain: another domain still has room.
	if _, ok := s.admit("other.example", "https://other.example/x"); !ok {
		t.Error("cap of one domain must not block another")
	}
}

func TestShaperUnbounded(t *testing.T) {
	s := newShaper(Options{PerShape: -1, MaxURLs: -1}.resolve())
	for i := range 50 {
		if _, ok := s.admit("example.com", "https://example.com/users/"+strconv.Itoa(i)); !ok {
			t.Fatalf("URL %d refused with bounds disabled", i)
		}
	}
}

func TestOptionsResolve(t *testing.T) {
	got := Options{}.resolve()
	if got.PerShape != DefaultPerShape || got.MaxURLs != DefaultMaxURLs ||
		got.CDXPageSize != DefaultCDXPageSize || got.CDXMaxRows != DefaultCDXMaxRows {
		t.Errorf("zero options = %+v, want defaults", got)
	}
	got = Options{PerShape: -1, MaxURLs: 9, CDXMaxRows: -1}.resolve()
	if got.PerShape != 0 || got.MaxURLs != 9 || got.CDXMaxRows != 0 {
		t.Errorf("resolve = %+v", got)
	}
}
