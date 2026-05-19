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

// TestCrossExtensionRedirectFalsePositive tests the cascade signature matching
// that fixes false positives for paths like sample.php.backup
func TestCrossExtensionRedirectFalsePositive(t *testing.T) {
	// Setup: Server returns same content for ALL requests (wildcard site)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>Generic redirect page - same for all paths</body></html>"))
	}))
	defer server.Close()

	// Create components
	learner := NewLearner(server.Client(), nil)
	learner.SetDelay(0) // No delay for tests

	cache := NewCache(learner)
	comparator := NewComparator(cache, learner)

	baseURL, err := url.Parse(server.URL + "/test.php")
	require.NoError(t, err)

	// Step 1: Learn "" (root) signature FIRST - critical for cascade matching
	t.Run("learn root signature first", func(t *testing.T) {
		rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
		sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
		require.NoError(t, err)
		t.Logf("Learned root signature with %d stable attrs", sig.StableAttributeCount())
	})

	// Step 2: Learn .php signature
	t.Run("learn php signature", func(t *testing.T) {
		phpKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ".php"}
		sig, err := cache.LearnAndCache(context.Background(), phpKey, baseURL)
		require.NoError(t, err)
		t.Logf("Learned .php signature with %d stable attrs", sig.StableAttributeCount())
	})

	// Step 3: Test sample.php.backup - should be detected as soft-404
	t.Run("cascade detects cross-extension soft-404", func(t *testing.T) {
		backupURL, err := url.Parse(server.URL + "/sample.php.backup")
		require.NoError(t, err)

		sample, err := learner.RequestAndExtract(context.Background(), backupURL)
		require.NoError(t, err)

		// Verify ExtractCacheKey gives .backup extension
		backupKey := ExtractCacheKey(backupURL)
		assert.Equal(t, ".backup", backupKey.Extension, "ExtractCacheKey should extract .backup")

		// OLD behavior: Matches() with .backup key should NOT match (no signature for .backup)
		assert.False(t, cache.Matches(backupKey, sample), "Matches() should NOT match .backup key")

		// NEW behavior: MatchesWithCascade() SHOULD match (via root or cross-extension)
		assert.True(t, cache.MatchesWithCascade(backupURL, sample),
			"MatchesWithCascade() should detect cross-extension soft-404")
	})

	// Step 4: Test CheckWildcardWithValidation returns FalsePositive
	// Note: Compare() calls CheckWildcardWithValidation which makes real HTTP requests
	// So we test the cascade check directly via CheckWildcardWithValidation
	t.Run("wildcard validation returns FalsePositive for cross-extension", func(t *testing.T) {
		backupURL, err := url.Parse(server.URL + "/sample.php.backup")
		require.NoError(t, err)

		sample, err := learner.RequestAndExtract(context.Background(), backupURL)
		require.NoError(t, err)

		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("")),
		}
		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()
		defer rc.Close()

		result, err := comparator.CheckWildcardWithValidation(context.Background(), backupURL, rc, sample)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result,
			"CheckWildcardWithValidation() should return FalsePositive for cross-extension soft-404")
	})
}

// TestRootSignatureMatchesAll verifies that "" (root) signature catches all paths
func TestRootSignatureMatchesAll(t *testing.T) {
	// Server returns same content for everything
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>Wildcard page</body></html>"))
	}))
	defer server.Close()

	learner := NewLearner(server.Client(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	baseURL, _ := url.Parse(server.URL + "/")

	// Learn ONLY root signature
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	_, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Test various paths - all should match root signature
	testPaths := []string{
		"/random123",
		"/test.php",
		"/test.php.bak",
		"/admin/config.json",
		"/api/v1/users.xml",
		"/backup/db.sql.gz",
	}

	for _, path := range testPaths {
		testURL, _ := url.Parse(server.URL + path)
		sample, err := learner.RequestAndExtract(context.Background(), testURL)
		require.NoError(t, err)

		matched := cache.MatchesWithCascade(testURL, sample)
		assert.True(t, matched, "Path %s should match root signature via cascade", path)
	}
}

// TestBaseExtensionFallback tests the .php.backup -> .php fallback
func TestBaseExtensionFallback(t *testing.T) {
	// Server returns DIFFERENT content for different extensions
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		// Return same content for .php and .php.* paths
		// (simulating a server that handles backup extensions same as original)
		_, _ = w.Write([]byte("<html><body>PHP error page</body></html>"))
	}))
	defer server.Close()

	learner := NewLearner(server.Client(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	baseURL, _ := url.Parse(server.URL + "/test.php")

	// Learn .php signature ONLY (no root)
	phpKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ".php"}
	_, err := cache.LearnAndCache(context.Background(), phpKey, baseURL)
	require.NoError(t, err)

	// Test .php.backup path
	backupURL, _ := url.Parse(server.URL + "/test.php.backup")
	sample, err := learner.RequestAndExtract(context.Background(), backupURL)
	require.NoError(t, err)

	// Direct match should fail (no .backup signature)
	backupKey := ExtractCacheKey(backupURL)
	assert.False(t, cache.Matches(backupKey, sample))

	// Cascade should match via base extension fallback (.php)
	assert.True(t, cache.MatchesWithCascade(backupURL, sample),
		"Should match via base extension fallback (.php)")
}

// TestMatchesAnyForHost verifies cross-extension matching
func TestMatchesAnyForHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><body>Same content</body></html>"))
	}))
	defer server.Close()

	learner := NewLearner(server.Client(), nil)
	learner.SetDelay(0)
	cache := NewCache(learner)

	baseURL, _ := url.Parse(server.URL + "/test.json")

	// Learn .json signature
	jsonKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ".json"}
	_, err := cache.LearnAndCache(context.Background(), jsonKey, baseURL)
	require.NoError(t, err)

	// Request with .xml extension (same content)
	xmlURL, _ := url.Parse(server.URL + "/test.xml")
	sample, err := learner.RequestAndExtract(context.Background(), xmlURL)
	require.NoError(t, err)

	// Should match via MatchesAnyForHostPath (using root path "/")
	assert.True(t, cache.MatchesAnyForHostPath(baseURL.Host, "/", sample),
		"Should match via cross-extension matching")
}

// TestHasSignaturesForHost verifies signature existence check
func TestHasSignaturesForHost(t *testing.T) {
	learner := NewLearner(nil, nil)
	cache := NewCache(learner)

	// Initially no signatures
	assert.False(t, cache.HasSignaturesForHost("example.com"))

	// Add a signature
	sig := &Signature{stable: map[Attribute]uint32{StatusCode: 200}}
	cache.Add(CacheKey{Host: "example.com", Path: "/", Extension: ".php"}, sig)

	// Now should have signatures
	assert.True(t, cache.HasSignaturesForHost("example.com"))

	// Different host should not have signatures
	assert.False(t, cache.HasSignaturesForHost("other.com"))
}
