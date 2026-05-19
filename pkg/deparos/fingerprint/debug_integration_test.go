package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
)

// TestDebugRedirectFingerprinting reproduces the runtime issue with verbose logging.
// This test simulates what happens when discovering extension variants that all redirect.
func TestDebugRedirectFingerprinting(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Server that redirects ALL paths to the homepage
	// This simulates gcas.stryker.com behavior
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log what path we received
		t.Logf("Server received: %s", r.URL.Path)

		// Redirect to homepage
		w.Header().Set("Location", "https://gcas.stryker.com/")
		w.WriteHeader(302)
	}))
	defer server.Close()

	// Use noRedirect client (matches engine.go behavior)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	learner := NewLearner(client, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Step 1: Learn root ("") signature - same as engine.go:504
	t.Log("=== STEP 1: Learning root signature ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned signature: %s", sig.DebugString())

	// Step 2: Simulate discovery of extension variants
	// These are the problematic paths from the user's issue
	extensionVariants := []string{
		"/2010.jspa",
		"/2010.jspa.TMP",
		"/2010.jspa.sav",
		"/2010.jspa.tar",
		"/2010.jspa.conf",
		"/0.aspx.bac",
		"/0.aspx.backup",
	}

	t.Log("=== STEP 2: Testing extension variants ===")
	for _, path := range extensionVariants {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequest("GET", testURL.String(), nil)

		resp, err := client.Get(testURL.String())
		require.NoError(t, err)

		// This simulates what the analyzer does
		sample, err := newSampleInternal(resp, nil, nil)
		require.NoError(t, err)
		_ = resp.Body.Close()

		// Check cascade matching
		t.Logf("\n--- Testing %s ---", path)
		t.Logf("Sample status: %d, location hash: %d",
			sample.GetHash(StatusCode), sample.GetHash(Location))

		// This is what comparator.Compare() does
		matched := cache.MatchesWithCascade(testURL, sample)
		if matched {
			t.Logf("MATCHED: %s → FalsePositive (filtered)", path)
		} else {
			t.Logf("NO MATCH: %s → will proceed to wildcard validation", path)

			// Create ResponseChain for CheckWildcardWithValidation
			rc := responsechain.NewResponseChain(resp, 0)
			_ = rc.Fill()

			// Call CheckWildcardWithValidation to see what happens
			result, err := comparator.CheckWildcardWithValidation(
				context.Background(), req.URL, rc, sample)
			rc.Close()
			require.NoError(t, err)
			t.Logf("Wildcard validation result: %v", result)

			// If TruePositive, this is the bug - redirect variants should be filtered
			if result == TruePositive {
				t.Errorf("BUG: %s returned TruePositive but should be FalsePositive", path)
			}
		}

		// Assert that all variants are detected as soft-404
		assert.True(t, matched || cache.MatchesWithCascade(testURL, sample),
			"Extension variant %s should match root redirect signature", path)
	}
}

// TestDebugLocationVariation tests what happens when Location header varies slightly
func TestDebugLocationVariation(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Server that redirects with slightly different Location headers
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Vary the Location header slightly (simulates real server behavior)
		var location string
		switch requestCount % 3 {
		case 0:
			location = "https://example.com/"
		case 1:
			location = "https://example.com" // No trailing slash
		case 2:
			location = "https://EXAMPLE.com/" // Different case
		}

		t.Logf("Request %d: %s -> Location: %s", requestCount, r.URL.Path, location)
		w.Header().Set("Location", location)
		w.WriteHeader(302)
	}))
	defer server.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	learner := NewLearner(client, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	baseURL, _ := url.Parse(server.URL + "/")

	// Learn signature with varying Location headers
	t.Log("=== Learning with varying Location headers ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned signature: %s", sig.DebugString())

	// Check if Location is stable
	hasLocation := sig.HasAttribute(Location)
	t.Logf("Location attribute stable: %v", hasLocation)

	if hasLocation {
		t.Log("ISSUE: Location is marked as stable but it varies!")
	} else {
		t.Log("OK: Location is NOT stable (as expected with varying values)")
	}

	// Test matching with a new request
	testURL, _ := url.Parse(server.URL + "/test")
	sample, _ := learner.RequestAndExtract(context.Background(), testURL)

	matched := cache.MatchesWithCascade(testURL, sample)
	t.Logf("New request matched: %v", matched)

	// If Location is not stable, signature should only have StatusCode
	// All 302 responses should match
	if !hasLocation {
		assert.True(t, matched, "Without stable Location, all 302s should match")
	}
}
