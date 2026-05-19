package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
	"go.uber.org/zap"
)

// TestRootWildcardFiltering tests that root-level paths are correctly filtered
// when the server redirects ALL paths to a login page.
//
// Scenario: Server redirects ALL paths (both random and real) to login
// Expected: All paths should be FalsePositive (soft-404)
func TestRootWildcardFiltering(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Server that redirects ALL paths to /login
	// This simulates www.hyattconnect.com behavior
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Server received: %s", r.URL.Path)

		// Redirect ALL paths to login page
		w.Header().Set("Location", "https://login.example.com/")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(302)
		_, _ = w.Write([]byte(`<html><head><title>Redirect</title></head><body>Redirecting...</body></html>`))
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

	// Step 1: Learn root ("") signature
	t.Log("=== STEP 1: Learning root signature ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned signature: %s", sig.DebugString())
	t.Logf("Stable attributes: %d", sig.StableAttributeCount())

	// Step 2: Test root-level paths (should all be FalsePositive)
	rootLevelPaths := []string{
		"/a",
		"/about",
		"/admin",
		"/backup",
		"/blog",
	}

	t.Log("=== STEP 2: Testing root-level paths ===")
	for _, path := range rootLevelPaths {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequest("GET", testURL.String(), nil)

		resp, err := client.Get(testURL.String())
		require.NoError(t, err)

		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		result, err := comparator.Compare(context.Background(), req, rc)
		rc.Close()

		require.NoError(t, err)
		t.Logf("%s → %v", path, result)

		// All should be FalsePositive (filtered) since server redirects everything
		assert.Equal(t, FalsePositive, result, "Path %s should be FalsePositive (soft-404)", path)
	}
}

// TestRootWildcardFiltering_MixedBehavior tests when server has different behavior
// for real paths vs random paths.
//
// Scenario:
// - Random paths: 404 Not Found
// - Real paths (/a, /about): 302 Redirect to login
// - This is different from pure wildcard!
//
// Expected: Real paths should be detected via wildcard validation
func TestRootWildcardFiltering_MixedBehavior(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Real paths that exist
	realPaths := map[string]bool{
		"/a":      true,
		"/about":  true,
		"/admin":  true,
		"/backup": true,
		"/blog":   true,
	}

	// Server with MIXED behavior:
	// - Known paths: 302 redirect to login
	// - Unknown paths: 404 not found
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		t.Logf("Server received: %s", path)

		if realPaths[path] {
			// Real path exists - redirect to login
			w.Header().Set("Location", "https://login.example.com/")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(302)
			_, _ = w.Write([]byte(`<html><head><title>Login Required</title></head><body>Please login</body></html>`))
		} else {
			// Random/unknown path - 404
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<html><head><title>Not Found</title></head><body>Page not found</body></html>`))
		}
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
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Step 1: Learn root ("") signature - will learn from 404 responses
	t.Log("=== STEP 1: Learning root signature ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned signature: %s", sig.DebugString())
	t.Logf("Stable attributes: %d", sig.StableAttributeCount())

	// The learned signature should be from 404 responses (status code 404)
	stableAttrs := sig.GetStableAttributes()
	t.Logf("Stable attribute hashes: %+v", stableAttrs)

	// Step 2: Test real paths
	// These should NOT match the 404 signature (different status code)
	// But wildcard validation should also detect them as different
	t.Log("=== STEP 2: Testing real paths ===")

	for path := range realPaths {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequest("GET", testURL.String(), nil)

		resp, err := client.Get(testURL.String())
		require.NoError(t, err)

		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		result, err := comparator.Compare(context.Background(), req, rc)
		rc.Close()

		require.NoError(t, err)
		t.Logf("%s (status %d) → %v", path, resp.StatusCode, result)

		// The question: Should these be TruePositive or FalsePositive?
		//
		// Current behavior: TruePositive (discovered)
		// - Because 302 doesn't match 404 signature
		// - Wildcard validation: random paths return 404 (no content)
		// - All 4 random paths have no content → isValid = true → TruePositive
		//
		// Expected behavior: TruePositive
		// - These ARE real resources that exist and redirect
		// - They differ from true 404s
		// - This is CORRECT behavior!

		// If server responds with 302 for real paths and 404 for random paths,
		// then real paths ARE legitimately different and should be discovered
		assert.Equal(t, TruePositive, result,
			"Path %s should be TruePositive - it's a real resource that differs from 404", path)
	}
}

// TestRootWildcardFiltering_AllRedirect tests the scenario from the original bug
// where the server redirects ALL paths (including random) to login.
//
// In this case, ALL paths should be FalsePositive.
func TestRootWildcardFiltering_AllRedirect(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	redirectLocation := "https://login.example.com/"

	// Server that redirects EVERYTHING to login
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Server received: %s", r.URL.Path)
		w.Header().Set("Location", redirectLocation)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(302)
		_, _ = w.Write([]byte(`<html><head><title>Redirect</title></head><body>Redirecting...</body></html>`))
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
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Step 1: Learn root ("") signature
	t.Log("=== STEP 1: Learning root signature ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned signature: %s", sig.DebugString())

	// Step 2: Test paths - all should match the learned signature
	testPaths := []string{"/a", "/about", "/admin", "/randomxyz123"}

	t.Log("=== STEP 2: Testing paths ===")
	for _, path := range testPaths {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequest("GET", testURL.String(), nil)

		resp, err := client.Get(testURL.String())
		require.NoError(t, err)

		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		// First check: Does it match the cached signature?
		sample, _ := NewSampleFromRC(rc)
		cascadeMatch := cache.MatchesWithCascade(testURL, sample)
		t.Logf("%s → cascade match: %v", path, cascadeMatch)

		if cascadeMatch {
			t.Logf("%s → FalsePositive (cascade match)", path)
			rc.Close()
			continue
		}

		// If no cascade match, proceed to full comparison
		result, err := comparator.Compare(context.Background(), req, rc)
		rc.Close()

		require.NoError(t, err)
		t.Logf("%s → %v", path, result)

		// All should be FalsePositive since server redirects everything identically
		assert.Equal(t, FalsePositive, result,
			"Path %s should be FalsePositive - server returns identical redirect for all paths", path)
	}
}

// TestPathVariationsForShortNames tests that path variations work correctly
// for single-character and short filenames.
func TestPathVariationsForShortNames(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		wantLen  int // Expected number of unique paths
	}{
		{
			name:     "single char /a",
			basePath: "/a",
			wantLen:  4, // Should still generate 4 paths
		},
		{
			name:     "short word /ab",
			basePath: "/ab",
			wantLen:  4,
		},
		{
			name:     "root path /",
			basePath: "/",
			wantLen:  4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, _ := url.Parse("http://example.com" + tt.basePath)
			paths, err := GenerateRandomPaths(baseURL)
			require.NoError(t, err)
			assert.Len(t, paths, 4)

			// Check all paths are unique (for longer names)
			uniquePaths := make(map[string]bool)
			for _, p := range paths {
				t.Logf("Generated: %s", p)
				uniquePaths[p] = true
			}

			// For single-char names, some variations may be identical
			// (Middle falls back to append for single-char names)
			if tt.basePath != "/" && len(tt.basePath) > 2 {
				// For paths with 2+ chars, check uniqueness
				assert.GreaterOrEqual(t, len(uniquePaths), 3,
					"Should generate at least 3 unique paths")
			}

			// All paths should be different from base path
			for _, p := range paths {
				assert.NotEqual(t, tt.basePath, p, "Generated path should differ from base")
			}
		})
	}
}

// TestWildcardValidation_SingleCharPaths tests wildcard validation for single-char paths
func TestWildcardValidation_SingleCharPaths(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Server that returns 200 OK for real paths, 404 for random
	realPaths := map[string]bool{
		"/a": true,
		"/b": true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		t.Logf("Server received: %s", path)

		if realPaths[path] {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<html><head><title>Page A</title></head><body>Content of page A</body></html>`))
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<html><head><title>Not Found</title></head><body>404</body></html>`))
		}
	}))
	defer server.Close()

	client := &http.Client{}

	learner := NewLearner(client, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Learn root signature
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned signature: %s", sig.DebugString())

	// Test /a - should be TruePositive (real resource)
	testURL, _ := url.Parse(server.URL + "/a")
	req, _ := http.NewRequest("GET", testURL.String(), nil)
	resp, err := client.Get(testURL.String())
	require.NoError(t, err)

	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()

	result, err := comparator.Compare(context.Background(), req, rc)
	rc.Close()

	require.NoError(t, err)
	t.Logf("/a → %v", result)

	// /a returns 200 OK, which is different from the 404 baseline
	// Wildcard validation: random paths return 404 (no content)
	// All 4 random paths have no content → isValid = true → TruePositive
	assert.Equal(t, TruePositive, result, "/a should be TruePositive - it's a real 200 OK resource")
}

// TestDebugHyattConnectScenario simulates the exact behavior from the bug report
func TestDebugHyattConnectScenario(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Simulate the hyattconnect.com scenario:
	// - All paths at /site/hc/static/site/* redirect to login
	// - Root paths may also redirect to login

	pathBehavior := func(path string) (int, string, string) {
		// Simulate redirect for all paths
		return 302, "https://login.hyattconnect.com/", `<html><body>Redirect</body></html>`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		t.Logf("Server received: %s", path)

		status, location, body := pathBehavior(path)
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
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
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Step 1: Learn root signature
	t.Log("=== Learning root signature ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Root signature: %s", sig.DebugString())

	// Step 2: Test the problematic paths from the bug report
	problemPaths := []string{
		"/a",
		"/about",
		"/admin",
		"/site/hc/static/site/hc",
		"/site/hc/static/site/default",
	}

	t.Log("=== Testing problem paths ===")
	for _, path := range problemPaths {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequest("GET", testURL.String(), nil)

		resp, err := client.Get(testURL.String())
		require.NoError(t, err)

		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		sample, _ := NewSampleFromRC(rc)

		// Debug: Log sample details
		t.Logf("Path: %s", path)
		t.Logf("  Status: %d", resp.StatusCode)
		t.Logf("  Sample StatusCode hash: %d", sample.GetHash(StatusCode))
		t.Logf("  Sample Location hash: %d", sample.GetHash(Location))

		// Check cascade match
		cascadeMatch := cache.MatchesWithCascade(testURL, sample)
		t.Logf("  Cascade match: %v", cascadeMatch)

		result, err := comparator.Compare(context.Background(), req, rc)
		rc.Close()
		require.NoError(t, err)

		t.Logf("  Result: %v", result)

		// Since ALL paths redirect identically, they should all be FalsePositive
		assert.Equal(t, FalsePositive, result,
			"Path %s should be FalsePositive - server returns identical redirect", path)
	}
}

// TestWildcardValidation_NestedPaths tests the fix for path-specific catch-alls
func TestWildcardValidation_NestedPaths(t *testing.T) {
	// Enable debug logging
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Server with path-specific catch-all at /site/hc/static/site/*
	// Only paths under this prefix redirect
	catchAllPrefix := "/site/hc/static/site/"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		t.Logf("Server received: %s", path)

		if strings.HasPrefix(path, catchAllPrefix) {
			// Paths under catch-all: redirect to login
			w.Header().Set("Location", "https://login.example.com/")
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(302)
			_, _ = w.Write([]byte(`<html><body>Login required</body></html>`))
		} else {
			// Other paths: 404
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<html><body>Not found</body></html>`))
		}
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
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Step 1: Learn root signature (from 404s at random root paths)
	t.Log("=== Learning root signature ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Root signature (404): %s", sig.DebugString())

	// Step 2: Test nested path - should be FalsePositive after fix
	nestedPath := "/site/hc/static/site/default"
	testURL, _ := url.Parse(server.URL + nestedPath)
	req, _ := http.NewRequest("GET", testURL.String(), nil)

	resp, err := client.Get(testURL.String())
	require.NoError(t, err)
	t.Logf("Response status: %d", resp.StatusCode)

	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()

	result, err := comparator.Compare(context.Background(), req, rc)
	rc.Close()
	require.NoError(t, err)

	t.Logf("%s → %v", nestedPath, result)

	// The original bug: paths under catch-all were marked TruePositive
	// because wildcard validation generated paths that ESCAPED the catch-all
	//
	// With the fix: test paths stay within catch-all, all return redirect
	// Therefore: FalsePositive (correctly filtered)
	assert.Equal(t, FalsePositive, result,
		"Nested path should be FalsePositive - all test paths should stay within catch-all")
}

// TestXMLDynamicRequestId_FingerprintMatching tests that fingerprint correctly
// matches responses with dynamic RequestId/HostId in XML error responses.
//
// Scenario: AWS S3-like error responses with random RequestId and HostId
// - 3 requests for baseline learning (each has different RequestId/HostId)
// - 4th request should still match the baseline
//
// Expected: 4th request should be FalsePositive (matches baseline signature)
func TestXMLDynamicRequestId_FingerprintMatching(t *testing.T) {
	zapLogger, _ := zap.NewDevelopment()
	SetLogger(zapLogger)
	defer SetLogger(zap.NewNop())

	// Counter for generating unique RequestId/HostId per request
	requestCounter := 0

	// Server that returns XML error with random RequestId/HostId
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCounter++
		t.Logf("Server received request #%d: %s", requestCounter, r.URL.Path)

		// Generate unique RequestId and HostId for each request
		requestId := strings.Repeat(string(rune('A'+requestCounter-1)), 32)
		hostId := strings.Repeat(string(rune('X'+requestCounter-1)), 64)

		xmlBody := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>` + requestId + `</RequestId><HostId>` + hostId + `</HostId></Error>`

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(xmlBody))

		t.Logf("  Response: 403 with RequestId=%s..., HostId=%s...", requestId[:8], hostId[:8])
	}))
	defer server.Close()

	client := &http.Client{}
	learner := NewLearner(client, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	// Step 1: Learn baseline (this will make 3 requests internally)
	t.Log("=== STEP 1: Learning baseline from 3 requests ===")
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	t.Logf("Learned signature with %d stable attributes:", sig.StableAttributeCount())
	stableAttrs := sig.GetStableAttributes()
	for attr, hash := range stableAttrs {
		t.Logf("  %s (#%d): %d (0x%08X)", attr.String(), attr, hash, hash)
	}

	// Step 2: Make 4th request and check if it matches
	t.Log("\n=== STEP 2: Testing 4th request (should match baseline) ===")
	testURL, _ := url.Parse(server.URL + "/test-path")
	req, _ := http.NewRequest("GET", testURL.String(), nil)

	resp, err := client.Get(testURL.String())
	require.NoError(t, err)

	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()

	// Get sample from 4th response
	sample, err := NewSampleFromRC(rc)
	require.NoError(t, err)

	t.Log("4th request sample attributes:")
	for attr := Attribute(1); attr <= MaxAttributeID; attr++ {
		if sample.HasAttribute(attr) {
			t.Logf("  %s (#%d): %d (0x%08X)", attr.String(), attr, sample.GetHash(attr), sample.GetHash(attr))
		}
	}

	// Check cascade match
	cascadeMatch := cache.MatchesWithCascade(testURL, sample)
	t.Logf("\nCascade match: %v", cascadeMatch)

	// Check signature match directly
	sigMatch := sig.Matches(sample)
	t.Logf("Signature match: %v", sigMatch)

	// Check partial match
	partialMatch := sig.PartialMatch(sample)
	t.Logf("Partial match: %.2f%%", partialMatch*100)

	// Run full comparison
	result, err := comparator.Compare(context.Background(), req, rc)
	rc.Close()
	require.NoError(t, err)

	t.Logf("\nFinal result: %v", result)

	// Analysis
	t.Log("\n=== ANALYSIS ===")
	t.Logf("Total requests made: %d (3 for baseline + 1 for test)", requestCounter)
	t.Logf("Stable attributes in signature: %d", sig.StableAttributeCount())

	// The key question: Does the 4th request match the baseline?
	// With dynamic RequestId/HostId:
	// - BodyContent, LimitedBodyContent, LastContent will NOT be stable (different hashes)
	// - StatusCode, ContentType, InitialContent SHOULD be stable
	//
	// If stable attributes >= 3 and all match, signature should match

	if result == FalsePositive {
		t.Log("✓ SUCCESS: 4th request correctly identified as FalsePositive (soft-404)")
		t.Log("  The fingerprint system correctly matched the response despite dynamic RequestId/HostId")
	} else {
		t.Log("✗ PROBLEM: 4th request identified as TruePositive")
		t.Log("  The fingerprint system failed to match due to dynamic content")
		t.Log("  This means baseline cannot be used for this type of response")
	}

	// We expect FalsePositive if the fingerprint system works correctly
	// But with current implementation, it may fail due to insufficient stable attributes
	assert.Equal(t, FalsePositive, result,
		"4th request should match baseline and be FalsePositive (soft-404)")
}
