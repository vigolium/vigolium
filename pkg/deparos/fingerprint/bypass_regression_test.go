package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// TestBaselineProbesPreserveBypassPrefix asserts the random sibling-path
// generators keep a path-normalization bypass prefix (%23/../) verbatim on the
// wire instead of collapsing it via path.Clean.
func TestBaselineProbesPreserveBypassPrefix(t *testing.T) {
	target, _ := url.Parse("https://host.example.com/%23/../metrics")
	paths, err := GenerateRandomPaths(target)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range paths {
		if !strings.HasPrefix(p, "/%23/../") {
			t.Errorf("probe %d = %q lost the /%%23/../ bypass prefix", i, p)
		}
		// And the URL that actually goes on the wire must still carry it.
		u := *target
		SetWirePath(&u, p)
		if !strings.Contains(u.RequestURI(), "%23") {
			t.Errorf("probe %d wire URI %q dropped %%23", i, u.RequestURI())
		}
	}
}

// TestBypassNotSuppressedByWildcardBaseline is the end-to-end guard: a target
// reached through a path-normalization bypass (backend 200) must NOT be
// classified as a wildcard/soft-404 just because the front proxy answers a 200
// catch-all for every *normalized* path.
func TestBypassNotSuppressedByWildcardBaseline(t *testing.T) {
	const backend = "process_cpu_seconds_total 42.7\nhttp_requests_total 12345\n"
	const frontSPA = "<!doctype html><title>Sign in</title><div id=app>please log in</div>"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Model the two routing layers: a raw "/%23/../" request-URI is forwarded
		// to the BACKEND (which normalizes it and only knows /metrics); any other
		// (already-normalized) path is answered by the FRONT PROXY catch-all.
		if strings.HasPrefix(r.RequestURI, "/%23/../") {
			if strings.TrimPrefix(r.RequestURI, "/%23/../") == "metrics" {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(backend))
				return
			}
			w.WriteHeader(http.StatusNotFound) // backend 404 for unknown endpoints
			_, _ = w.Write([]byte("backend: not found"))
			return
		}
		// Front-proxy catch-all: any normalized path 200s with the login SPA.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(frontSPA))
	}))
	defer srv.Close()

	client := srv.Client()
	comp := NewComparator(NewCache(NewLearner(client, nil)), NewLearner(client, nil))

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/%23/../metrics", nil)

	// Mirror production: the discovery engine learns the directory's soft-404
	// baseline (learnBaselineFingerprintsForDirectory) BEFORE validating hits.
	// With the fix, that baseline is sampled through the bypass prefix, so it
	// captures the backend 404 — not the front-proxy 200 catch-all.
	if _, err := comp.cache.LearnAndCache(context.Background(), ExtractCacheKey(req.URL), req.URL); err != nil {
		t.Fatalf("baseline learn: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rc := responsechain.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	result, err := comp.Compare(context.Background(), req, rc)
	if err != nil {
		t.Fatal(err)
	}
	if result == FalsePositive {
		t.Fatalf("genuine backend 200 was suppressed as a wildcard/soft-404 (result=%s)", result)
	}
	if result != TruePositive {
		t.Logf("note: result=%s (acceptable as long as not FalsePositive)", result)
	}
}
