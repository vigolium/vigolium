package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// noRedirectClient returns an HTTP client that does NOT follow redirects.
// This is required for testing redirect fingerprinting - we want to capture
// the redirect response itself, not follow it.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// TestRedirectFingerprintLearning verifies that redirect responses can be learned
// as fingerprint signatures. Key attributes: StatusCode (302) and Location header.
func TestRedirectFingerprintLearning(t *testing.T) {
	// Server returns 302 redirect to /home for ALL paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/home")
		w.WriteHeader(302)
	}))
	defer server.Close()

	learner := NewLearner(noRedirectClient(), nil)
	learner.SetDelay(0) // No delay for tests

	cache := NewCache(learner)

	baseURL, err := url.Parse(server.URL + "/test")
	require.NoError(t, err)

	// Learn root ("") signature from redirect responses
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Verify signature learned from redirect
	t.Logf("Learned redirect signature with %d stable attrs", sig.StableAttributeCount())

	// Must have StatusCode (attribute 2) - critical for matching
	assert.True(t, sig.HasAttribute(StatusCode),
		"Signature must have StatusCode attribute for redirect detection")
	assert.Equal(t, uint32(302), sig.GetStableAttributes()[StatusCode],
		"StatusCode should be 302")

	// Must have Location header (attribute 32) - key differentiator for redirects
	assert.True(t, sig.HasAttribute(Location),
		"Signature must have Location attribute for redirect detection")
}

// TestRedirectSoftFalsePositive verifies that identical redirect responses
// are detected as soft-404 (FalsePositive) after learning.
func TestRedirectSoftFalsePositive(t *testing.T) {
	// Server redirects ALL non-existent paths to /
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/")
		w.WriteHeader(302)
	}))
	defer server.Close()

	learner := NewLearner(noRedirectClient(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	baseURL, _ := url.Parse(server.URL + "/")

	// Step 1: Learn root signature
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	_, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Step 2: Test new random paths - all should be detected as soft-404
	testPaths := []string{
		"/random123",
		"/does-not-exist",
		"/admin.php",
		"/backup.tar.gz",
	}

	for _, path := range testPaths {
		testURL, _ := url.Parse(server.URL + path)
		sample, err := learner.RequestAndExtract(context.Background(), testURL)
		require.NoError(t, err)

		// Should match via cascade (root signature)
		assert.True(t, cache.MatchesWithCascade(testURL, sample),
			"Path %s should match root redirect signature", path)

		// CheckWildcardWithValidation should return FalsePositive
		resp := &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader(""))}
		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()
		result, err := comparator.CheckWildcardWithValidation(
			context.Background(), testURL, rc, sample)
		rc.Close()
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result,
			"Path %s should be detected as FalsePositive", path)
	}
}

// TestRedirectVariantFiltering reproduces the exact user issue:
// Extension variants like 2010.jspa.TMP, 2010.jspa.sav all redirect
// to the same location and should be filtered as soft-404.
func TestRedirectVariantFiltering(t *testing.T) {
	// Server behavior: ALL paths redirect to homepage
	// This simulates the real gcas.stryker.com behavior
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://gcas.stryker.com/")
		w.WriteHeader(302)
	}))
	defer server.Close()

	learner := NewLearner(noRedirectClient(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	baseURL, _ := url.Parse(server.URL + "/")

	// Step 1: Learn root signature FIRST (critical for cascade matching)
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	t.Logf("Learned root signature: %s", sig.Debug())

	// Step 2: Test extension variants - these are the problematic cases
	// All should be filtered because they redirect to same location
	extensionVariants := []string{
		"/2010.jspa",
		"/2010.jspa.TMP",
		"/2010.jspa.sav",
		"/2010.jspa.tar",
		"/2010.jspa.conf",
		"/2010.jspa.0",
		"/2010.jspa.~bk",
		"/2010.jspa.zip",
		"/2010.jspa.log",
		"/2010.jspa.old",
		"/2010.jspa.gz",
		"/2010.jspa.csproj",
	}

	for _, path := range extensionVariants {
		testURL, _ := url.Parse(server.URL + path)
		sample, err := learner.RequestAndExtract(context.Background(), testURL)
		require.NoError(t, err)

		// Cascade should match root signature
		matched := cache.MatchesWithCascade(testURL, sample)
		assert.True(t, matched,
			"Extension variant %s should match root redirect signature via cascade", path)

		// CheckWildcardWithValidation should return FalsePositive
		resp := &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader(""))}
		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()
		result, err := comparator.CheckWildcardWithValidation(
			context.Background(), testURL, rc, sample)
		rc.Close()
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result,
			"Extension variant %s should be FalsePositive", path)
	}
}

// TestRedirectDifferentLocations verifies that redirects to DIFFERENT locations
// are NOT considered soft-404 when they have stable different Location headers.
//
// Important: When learning a signature, 3 random paths are tested. If each path
// redirects to a DIFFERENT location (e.g., /random1 → /random1/), then Location
// is NOT stable across samples and won't be part of the signature.
//
// This test demonstrates two scenarios:
// 1. Server A: ALL paths → same location (wildcard, Location IS stable)
// 2. Server B: /path → /path/ (trailing slash, Location is NOT stable)
func TestRedirectDifferentLocations(t *testing.T) {
	t.Run("same_location_is_stable", func(t *testing.T) {
		// Server redirects ALL paths to SAME location → Location IS stable
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/home")
			w.WriteHeader(301)
		}))
		defer server.Close()

		learner := NewLearner(noRedirectClient(), nil)
		learner.SetDelay(0)
		cache := NewCache(learner)

		baseURL, _ := url.Parse(server.URL + "/test")

		// Learn signature - all random paths redirect to /home
		rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
		sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
		require.NoError(t, err)

		// Location SHOULD be stable because all paths redirect to /home
		assert.True(t, sig.HasAttribute(Location),
			"Location should be stable when all paths redirect to same target")

		// Any new path should match because Location is same
		newURL, _ := url.Parse(server.URL + "/random")
		sample, _ := learner.RequestAndExtract(context.Background(), newURL)
		assert.True(t, cache.MatchesWithCascade(newURL, sample),
			"Same Location should match learned signature")
	})

	t.Run("different_locations_not_stable", func(t *testing.T) {
		// Server redirects each path to its own trailing-slash version
		// e.g., /admin → /admin/, /api → /api/
		// In this case, Location is NOT stable across the 3 learning samples
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			location := r.URL.Path
			if location[len(location)-1] != '/' {
				location += "/"
			}
			w.Header().Set("Location", location)
			w.WriteHeader(301)
		}))
		defer server.Close()

		learner := NewLearner(noRedirectClient(), nil)
		learner.SetDelay(0)
		cache := NewCache(learner)

		baseURL, _ := url.Parse(server.URL + "/admin")

		// Learn signature - Location will NOT be stable (different for each random path)
		rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
		sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
		require.NoError(t, err)

		// Location should NOT be stable because each path has different Location
		assert.False(t, sig.HasAttribute(Location),
			"Location should NOT be stable when each path has different redirect target")

		// Since only StatusCode is stable (301), ALL 301 responses will match
		// This is expected behavior - the signature says "all 301 redirects are soft-404"
		apiURL, _ := url.Parse(server.URL + "/api")
		apiSample, _ := learner.RequestAndExtract(context.Background(), apiURL)
		assert.True(t, cache.MatchesWithCascade(apiURL, apiSample),
			"When Location is not stable, all 301s match (signature only has StatusCode)")
	})
}

// TestRedirectVs200 verifies that a 302 redirect signature does NOT match
// a 200 OK response (and vice versa).
func TestRedirectVs200(t *testing.T) {
	// Server alternates between redirect and 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/found" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("<html>Real page</html>"))
		} else {
			w.Header().Set("Location", "/")
			w.WriteHeader(302)
		}
	}))
	defer server.Close()

	learner := NewLearner(noRedirectClient(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	baseURL, _ := url.Parse(server.URL + "/notfound")

	// Learn redirect signature
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	t.Logf("Learned redirect signature with StatusCode=%d",
		sig.GetStableAttributes()[StatusCode])

	// Get sample from 200 OK response
	foundURL, _ := url.Parse(server.URL + "/found")
	okSample, err := learner.RequestAndExtract(context.Background(), foundURL)
	require.NoError(t, err)

	t.Logf("200 OK sample StatusCode=%d", okSample.GetHash(StatusCode))

	// 200 OK should NOT match 302 redirect signature
	matched := cache.MatchesWithCascade(foundURL, okSample)
	assert.False(t, matched,
		"200 OK response should NOT match 302 redirect signature")
}

// TestRedirectSignatureAttributes verifies all expected attributes are captured
// for redirect responses.
func TestRedirectSignatureAttributes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/target")
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Redirect-Reason", "not-found")
		w.WriteHeader(302)
		// Some servers include body with redirect
		_, _ = w.Write([]byte("<html><head><title>Redirecting...</title></head></html>"))
	}))
	defer server.Close()

	learner := NewLearner(noRedirectClient(), nil)
	learner.SetDelay(0)

	testURL, _ := url.Parse(server.URL + "/test")
	sample, err := learner.RequestAndExtract(context.Background(), testURL)
	require.NoError(t, err)

	// Check all expected attributes for redirect
	t.Run("StatusCode", func(t *testing.T) {
		assert.True(t, sample.HasAttribute(StatusCode))
		assert.Equal(t, uint32(302), sample.GetHash(StatusCode))
	})

	t.Run("Location", func(t *testing.T) {
		assert.True(t, sample.HasAttribute(Location))
		assert.NotZero(t, sample.GetHash(Location))
	})

	t.Run("ContentType", func(t *testing.T) {
		assert.True(t, sample.HasAttribute(ContentType))
	})

	t.Run("BodyContent", func(t *testing.T) {
		assert.True(t, sample.HasAttribute(BodyContent))
	})

	t.Run("PageTitle", func(t *testing.T) {
		// HTML is parsed, title should be extracted
		assert.True(t, sample.HasAttribute(PageTitle))
	})
}

// TestRedirect301Vs302 verifies that 301 and 302 create different signatures
// (StatusCode is a stable attribute that must match exactly).
func TestRedirect301Vs302(t *testing.T) {
	// Server returns 301 for /permanent, 302 for everything else
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/target")
		if r.URL.Path == "/permanent" {
			w.WriteHeader(301)
		} else {
			w.WriteHeader(302)
		}
	}))
	defer server.Close()

	learner := NewLearner(noRedirectClient(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	// Learn 302 signature
	tempURL, _ := url.Parse(server.URL + "/temporary")
	rootKey := CacheKey{Host: tempURL.Host, Path: "/", Extension: ""}
	sig302, err := cache.LearnAndCache(context.Background(), rootKey, tempURL)
	require.NoError(t, err)

	t.Logf("302 signature: StatusCode=%d", sig302.GetStableAttributes()[StatusCode])

	// Get 301 sample
	permURL, _ := url.Parse(server.URL + "/permanent")
	sample301, err := learner.RequestAndExtract(context.Background(), permURL)
	require.NoError(t, err)

	t.Logf("301 sample: StatusCode=%d", sample301.GetHash(StatusCode))

	// 301 should NOT match 302 signature
	matched := cache.MatchesWithCascade(permURL, sample301)
	assert.False(t, matched,
		"301 Permanent Redirect should NOT match 302 Temporary Redirect signature")
}
