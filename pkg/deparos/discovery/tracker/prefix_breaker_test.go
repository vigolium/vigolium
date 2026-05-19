package tracker

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func TestPrefixOf(t *testing.T) {
	cases := []struct {
		path string
		n    int
		want string
	}{
		{"/ftp/api/x", 1, "/ftp"},
		{"/ftp/api/x", 2, "/ftp/api"},
		{"/ftp", 1, "/ftp"},
		{"/ftp", 2, "/ftp"},
		{"/ftp/", 1, "/ftp"},
		{"/", 1, ""},
		{"", 1, ""},
		{"/a/b/c/d", 3, "/a/b/c"},
		{"/a/b/c/d", 0, ""},
		{"/a/b/c/d", -1, ""},
	}
	for _, tc := range cases {
		got := PrefixOf(tc.path, tc.n)
		if got != tc.want {
			t.Errorf("PrefixOf(%q, %d) = %q, want %q", tc.path, tc.n, got, tc.want)
		}
	}
}

func TestNormalizeContentType(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"text/html", "text/html"},
		{"text/html; charset=utf-8", "text/html"},
		{"  application/JSON ; q=1 ", "application/json"},
		{"", ""},
	}
	for _, tc := range cases {
		got := normalizeContentType(tc.in)
		if got != tc.want {
			t.Errorf("normalizeContentType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLengthBucket(t *testing.T) {
	if lengthBucket(0, 256) != 0 {
		t.Error("0/256 should bucket to 0")
	}
	if lengthBucket(255, 256) != 0 {
		t.Error("255/256 should bucket to 0")
	}
	if lengthBucket(256, 256) != 1 {
		t.Error("256/256 should bucket to 1")
	}
	if lengthBucket(513, 256) != 2 {
		t.Error("513/256 should bucket to 2")
	}
	if lengthBucket(1000, 0) != 0 {
		t.Error("zero width should collapse to 0")
	}
}

func TestPrefixBreaker_DisabledIsNoOp(t *testing.T) {
	b := NewPrefixBreaker(BreakerConfig{Enabled: false, MinSamples: 2, TripRatio: 0.5, PrefixSegments: 1, LengthBucket: 256})
	u := mustURL(t, "http://h/ftp/x")
	for range 10 {
		if _, tripped := b.Observe(u, 403, "text/html", 100); tripped {
			t.Fatal("disabled breaker must never trip")
		}
	}
	if b.IsDead(u) {
		t.Fatal("disabled breaker must report not dead")
	}
}

func TestPrefixBreaker_TripsOnUniformResponses(t *testing.T) {
	b := NewPrefixBreaker(BreakerConfig{
		Enabled: true, MinSamples: 5, TripRatio: 0.9, PrefixSegments: 1, LengthBucket: 256,
	})
	u := func(p string) *url.URL { return mustURL(t, "http://example.com"+p) }

	// 4 uniform observations — below MinSamples, no trip
	for i, p := range []string{"/ftp/a", "/ftp/b", "/ftp/c", "/ftp/d"} {
		if _, tripped := b.Observe(u(p), 403, "text/html; charset=utf-8", 200); tripped {
			t.Fatalf("trip too early at iter %d (path=%s)", i, p)
		}
	}
	if b.IsDead(u("/ftp/anything")) {
		t.Fatal("must not be dead before MinSamples")
	}

	// 5th sample crosses MinSamples — uniform, must trip
	reason, tripped := b.Observe(u("/ftp/e"), 403, "text/html", 220)
	if !tripped {
		t.Fatal("expected trip on 5th uniform sample")
	}
	if reason.Host != "example.com" || reason.Prefix != "/ftp" {
		t.Errorf("wrong reason key: host=%q prefix=%q", reason.Host, reason.Prefix)
	}
	if reason.DominantStatus != 403 || reason.DominantCT != "text/html" {
		t.Errorf("wrong dominant: status=%d ct=%q", reason.DominantStatus, reason.DominantCT)
	}
	if reason.DominantCount != 5 || reason.Samples != 5 {
		t.Errorf("wrong counts: dominant=%d total=%d", reason.DominantCount, reason.Samples)
	}

	if !b.IsDead(u("/ftp/anything")) {
		t.Fatal("expected /ftp prefix to be dead")
	}
	if b.IsDead(u("/other/path")) {
		t.Fatal("unrelated prefix must not be dead")
	}

	// Subsequent observations must not re-trip (return false).
	if _, tripped := b.Observe(u("/ftp/zzz"), 403, "text/html", 200); tripped {
		t.Fatal("must not re-trip after first trip")
	}
	if b.TrippedCount() != 1 {
		t.Errorf("TrippedCount=%d, want 1", b.TrippedCount())
	}
}

func TestPrefixBreaker_DoesNotTripOnDiverseResponses(t *testing.T) {
	b := NewPrefixBreaker(BreakerConfig{
		Enabled: true, MinSamples: 5, TripRatio: 0.9, PrefixSegments: 1, LengthBucket: 256,
	})
	u := func(p string) *url.URL { return mustURL(t, "http://h"+p) }

	// Mix of statuses — no single tuple dominates 90%
	b.Observe(u("/api/users"), 200, "application/json", 1000)
	b.Observe(u("/api/products"), 200, "application/json", 5000)
	b.Observe(u("/api/admin"), 401, "application/json", 50)
	b.Observe(u("/api/missing"), 404, "text/html", 800)
	b.Observe(u("/api/error"), 500, "text/html", 300)
	b.Observe(u("/api/orders"), 200, "application/json", 2500)

	if b.IsDead(u("/api/x")) {
		t.Fatal("diverse responses must not trip breaker")
	}
}

func TestPrefixBreaker_LengthBucketingDistinguishesContent(t *testing.T) {
	// Real listing pages have distinct lengths — they should NOT trip even on
	// uniform status+content-type.
	b := NewPrefixBreaker(BreakerConfig{
		Enabled: true, MinSamples: 5, TripRatio: 0.9, PrefixSegments: 1, LengthBucket: 256,
	})
	u := func(p string) *url.URL { return mustURL(t, "http://h"+p) }

	// All 200 OK + html, but lengths span > 1KB → spread across multiple buckets
	b.Observe(u("/blog/a"), 200, "text/html", 100)
	b.Observe(u("/blog/b"), 200, "text/html", 500)
	b.Observe(u("/blog/c"), 200, "text/html", 900)
	b.Observe(u("/blog/d"), 200, "text/html", 1300)
	b.Observe(u("/blog/e"), 200, "text/html", 1700)

	if b.IsDead(u("/blog/x")) {
		t.Fatal("diverse-length 200s must not trip breaker")
	}
}

func TestPrefixBreaker_PerHostIsolation(t *testing.T) {
	b := NewPrefixBreaker(BreakerConfig{
		Enabled: true, MinSamples: 3, TripRatio: 0.9, PrefixSegments: 1, LengthBucket: 256,
	})
	a := func(p string) *url.URL { return mustURL(t, "http://a.com"+p) }
	bb := func(p string) *url.URL { return mustURL(t, "http://b.com"+p) }

	for _, p := range []string{"/ftp/x", "/ftp/y", "/ftp/z"} {
		b.Observe(a(p), 403, "text/html", 100)
	}
	if !b.IsDead(a("/ftp/q")) {
		t.Fatal("a.com /ftp should be dead")
	}
	if b.IsDead(bb("/ftp/q")) {
		t.Fatal("b.com /ftp must not be affected by a.com state")
	}
}

func TestPrefixBreaker_RootPathIgnored(t *testing.T) {
	// Probes against "/" should not feed any prefix bucket — there's no
	// prefix to blame and the root being uniform doesn't help us.
	b := NewPrefixBreaker(BreakerConfig{
		Enabled: true, MinSamples: 2, TripRatio: 0.5, PrefixSegments: 1, LengthBucket: 256,
	})
	u := mustURL(t, "http://h/")
	for range 5 {
		if _, tripped := b.Observe(u, 403, "text/html", 100); tripped {
			t.Fatal("root path must never trip")
		}
	}
	if b.IsDead(u) {
		t.Fatal("root path can never be dead")
	}
}

func TestPrefixBreaker_NilSafe(t *testing.T) {
	var b *PrefixBreaker
	if _, tripped := b.Observe(mustURL(t, "http://h/x"), 200, "text/html", 100); tripped {
		t.Fatal("nil breaker must return false")
	}
	if b.IsDead(mustURL(t, "http://h/x")) {
		t.Fatal("nil breaker must report not dead")
	}
	if b.TrippedCount() != 0 {
		t.Fatal("nil breaker count must be 0")
	}
}
