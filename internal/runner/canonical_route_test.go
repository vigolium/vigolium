package runner

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// TestCanonicalRouteCollapsesIDs verifies id-like path segments collapse so a
// route-template family maps to one key, while stable route labels stay distinct.
func TestCanonicalRouteCollapsesIDs(t *testing.T) {
	same := [][2]string{
		{"https://x.example/product/1", "https://x.example/product/2"},
		{"https://x.example/users/550e8400-e29b-41d4-a716-446655440000", "https://x.example/users/6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{"https://x.example/orders/1000000042/view", "https://x.example/orders/999999999/view"},
		{"https://x.example/a/9f8e7d6c5b4a3f2e1d0c9b8a", "https://x.example/a/00112233445566778899aabb"},
		{"https://x.example/list?page=2&sort=asc", "https://x.example/list?page=9&sort=desc"}, // query values ignored
	}
	for _, p := range same {
		if a, b := canonicalRoute(mustURL(t, p[0])), canonicalRoute(mustURL(t, p[1])); a != b {
			t.Errorf("expected same route:\n %s -> %s\n %s -> %s", p[0], a, p[1], b)
		}
	}

	distinct := [][2]string{
		{"https://x.example/products", "https://x.example/settings"},
		{"https://x.example/api/v1/users", "https://x.example/api/v2/users"}, // version labels kept
		{"https://x.example/list?page=1", "https://x.example/list?filter=1"}, // different query keys
		{"https://a.example/x", "https://b.example/x"},                       // different host
	}
	for _, p := range distinct {
		if a, b := canonicalRoute(mustURL(t, p[0])), canonicalRoute(mustURL(t, p[1])); a == b {
			t.Errorf("expected distinct routes but both = %q (%s vs %s)", a, p[0], p[1])
		}
	}
}

// TestReSpiderRouteDedup verifies the selection collapses same-template data pages
// to a single seed even when their bodies (and thus shell hashes) differ.
func TestReSpiderRouteDedup(t *testing.T) {
	// Two server-rendered product pages: same template, different body content, so
	// shellFingerprint differs but canonicalRoute matches → one seed kept.
	evals := []respiderEvaluated{
		{
			source: "sourcemap", hostname: "shop.example", url: "https://shop.example/product/1",
			decodeOK: true, verdict: respiderVerdict{Keep: true, Reason: "interactive", Score: 20, ShellHash: "hashA"},
		},
		{
			source: "sourcemap", hostname: "shop.example", url: "https://shop.example/product/2",
			decodeOK: true, verdict: respiderVerdict{Keep: true, Reason: "interactive", Score: 20, ShellHash: "hashB"},
		},
	}
	chosen, skips, kept := selectReSpiderSeedsFromEvaluated(evals, 10, 10)
	if kept != 1 || len(chosen) != 1 {
		t.Fatalf("expected 1 seed kept, got kept=%d chosen=%d", kept, len(chosen))
	}
	if skips["dup-route"] != 1 {
		t.Errorf("expected dup-route=1, got %v", skips)
	}
}
