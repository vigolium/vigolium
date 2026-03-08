package http

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

	"github.com/vigolium/vigolium/pkg/deparos/fingerprint"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// createTestResponseChain creates a ResponseChain for testing.
func createTestResponseChain(resp *http.Response) *responsechain.ResponseChain {
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	return rc
}

// createTestResponseChainFromParts creates a ResponseChain from status, headers, body.
func createTestResponseChainFromParts(statusCode int, headers http.Header, body string) *responsechain.ResponseChain {
	if headers == nil {
		headers = make(http.Header)
	}
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	return rc
}

// noRedirectClient returns an HTTP client that does NOT follow redirects.
// This is required for testing fingerprinting of redirect responses.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// TestAnalyzer_302_FingerprintCheck verifies that 302 redirect responses
// go through fingerprint comparison and can be detected as soft-404.
func TestAnalyzer_302_FingerprintCheck(t *testing.T) {
	// Server redirects ALL paths to /
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/")
		w.WriteHeader(302)
	}))
	defer server.Close()

	// Create fingerprint infrastructure with noRedirect client
	client := noRedirectClient()
	learner := fingerprint.NewLearner(client, nil)
	learner.SetDelay(0)
	cache := fingerprint.NewCache(learner)
	comparator := fingerprint.NewComparator(cache, learner)

	// Create analyzer with fingerprint support
	analyzer := NewAnalyzer(comparator)

	baseURL, _ := url.Parse(server.URL + "/")

	// Step 1: Learn root signature (simulates engine initialization)
	rootKey := fingerprint.CacheKey{Host: baseURL.Host, Extension: ""}
	_, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Step 2: Test that new redirect is detected as soft-404
	testURL, _ := url.Parse(server.URL + "/random123")
	req, _ := http.NewRequest("GET", testURL.String(), nil)

	resp, err := client.Get(testURL.String())
	require.NoError(t, err)

	rc := createTestResponseChain(resp)
	defer rc.Close()

	// Analyze should return false (soft-404)
	found, err := analyzer.Analyze(context.Background(), req, rc)
	require.NoError(t, err)

	assert.False(t, found,
		"302 redirect matching learned signature should return false (not found)")
}

// TestAnalyzer_302_ExtensionVariants reproduces the exact user issue:
// 2010.jspa.TMP, 2010.jspa.sav, etc. all redirect to same location.
func TestAnalyzer_302_ExtensionVariants(t *testing.T) {
	// Server redirects ALL paths to homepage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/")
		w.WriteHeader(302)
	}))
	defer server.Close()

	client := noRedirectClient()
	learner := fingerprint.NewLearner(client, nil)
	learner.SetDelay(0)
	cache := fingerprint.NewCache(learner)
	comparator := fingerprint.NewComparator(cache, learner)
	analyzer := NewAnalyzer(comparator)

	baseURL, _ := url.Parse(server.URL + "/")

	// Learn root signature
	rootKey := fingerprint.CacheKey{Host: baseURL.Host, Extension: ""}
	_, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Test extension variants - these should all be filtered
	variants := []string{
		"/2010.jspa",
		"/2010.jspa.TMP",
		"/2010.jspa.sav",
		"/2010.jspa.tar",
		"/2010.jspa.conf",
		"/2010.jspa.zip",
		"/2010.jspa.old",
	}

	for _, path := range variants {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequest("GET", testURL.String(), nil)

		resp, err := client.Get(testURL.String())
		require.NoError(t, err)

		rc := createTestResponseChain(resp)
		found, err := analyzer.Analyze(context.Background(), req, rc)
		rc.Close()
		require.NoError(t, err)

		assert.False(t, found,
			"Extension variant %s should return false (not found)", path)
	}
}

// TestAnalyzer_AllStatusCodes_FingerprintFirst verifies that ALL status codes
// go through fingerprint check FIRST before status code classification.
func TestAnalyzer_AllStatusCodes_FingerprintFirst(t *testing.T) {
	testCases := []struct {
		name           string
		statusCode     int
		location       string // for redirects
		body           string
		expectedBefore bool // Before fingerprint check
		expectedAfter  bool // After learning + matching
	}{
		{
			name:           "200 OK wildcard",
			statusCode:     200,
			body:           "<html><body>Generic page</body></html>",
			expectedBefore: true,
			expectedAfter:  false,
		},
		{
			name:           "302 Redirect wildcard",
			statusCode:     302,
			location:       "/",
			expectedBefore: true,
			expectedAfter:  false,
		},
		{
			name:           "301 Permanent Redirect wildcard",
			statusCode:     301,
			location:       "/home",
			expectedBefore: true,
			expectedAfter:  false,
		},
		{
			name:           "404 Not Found wildcard",
			statusCode:     404,
			body:           "<html><body>Custom 404 page</body></html>",
			expectedBefore: false,
			expectedAfter:  false,
		},
		{
			name:           "401 Unauthorized wildcard",
			statusCode:     401,
			body:           "<html><body>Login required</body></html>",
			expectedBefore: true,
			expectedAfter:  false,
		},
		{
			name:           "403 Forbidden wildcard",
			statusCode:     403,
			body:           "<html><body>Access denied</body></html>",
			expectedBefore: true,
			expectedAfter:  false,
		},
		{
			name:           "500 Server Error wildcard",
			statusCode:     500,
			body:           "<html><body>Server error</body></html>",
			expectedBefore: true,
			expectedAfter:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create server that returns this status code for ALL paths
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				if tc.body != "" {
					w.Header().Set("Content-Type", "text/html")
				}
				w.WriteHeader(tc.statusCode)
				if tc.body != "" {
					_, _ = w.Write([]byte(tc.body))
				}
			}))
			defer server.Close()

			// Use noRedirectClient for redirects, default for others
			client := noRedirectClient()
			learner := fingerprint.NewLearner(client, nil)
			learner.SetDelay(0)
			cache := fingerprint.NewCache(learner)
			comparator := fingerprint.NewComparator(cache, learner)
			analyzer := NewAnalyzer(comparator)

			baseURL, _ := url.Parse(server.URL + "/")

			// Learn root signature
			rootKey := fingerprint.CacheKey{Host: baseURL.Host, Extension: ""}
			_, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
			require.NoError(t, err)

			// Test new path - should be detected as soft-404
			testURL, _ := url.Parse(server.URL + "/newpath")
			req, _ := http.NewRequest("GET", testURL.String(), nil)

			resp, err := client.Get(testURL.String())
			require.NoError(t, err)

			rc := createTestResponseChain(resp)
			defer rc.Close()

			found, err := analyzer.Analyze(context.Background(), req, rc)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedAfter, found,
				"After learning, %s should return %v", tc.name, tc.expectedAfter)
		})
	}
}

// TestAnalyzer_NoComparator verifies that analyzer still works without comparator.
func TestAnalyzer_NoComparator(t *testing.T) {
	analyzer := NewAnalyzer(nil)

	testCases := []struct {
		statusCode int
		expected   bool
	}{
		{200, true},
		{302, true},
		{404, false},
		{401, true},
		{500, true},
	}

	for _, tc := range testCases {
		req, _ := http.NewRequest("GET", "http://example.com/test", nil)
		rc := createTestResponseChainFromParts(tc.statusCode, nil, "")
		defer rc.Close()

		found, err := analyzer.Analyze(context.Background(), req, rc)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, found,
			"Status code %d should return %v", tc.statusCode, tc.expected)
	}
}

// TestAnalyzer_RedirectDifferentLocations verifies that redirects with
// different Location headers per path create unstable Location attribute.
// When Location is unstable, only StatusCode is in the signature,
// so ALL 301 responses will match.
func TestAnalyzer_RedirectDifferentLocations(t *testing.T) {
	// Server returns different Location for different paths
	// e.g., /admin → /admin/, /api → /api/
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		location := r.URL.Path + "/"
		w.Header().Set("Location", location)
		w.WriteHeader(301)
	}))
	defer server.Close()

	client := noRedirectClient()
	learner := fingerprint.NewLearner(client, nil)
	learner.SetDelay(0)
	cache := fingerprint.NewCache(learner)
	comparator := fingerprint.NewComparator(cache, learner)
	analyzer := NewAnalyzer(comparator)

	baseURL, _ := url.Parse(server.URL + "/admin")

	// Learn signature for /admin → /admin/
	// Note: Learning samples 3 random paths, each with different Location
	// So Location will NOT be stable, only StatusCode (301) is stable
	rootKey := fingerprint.CacheKey{Host: baseURL.Host, Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Verify Location is NOT stable (because each random path has different Location)
	assert.False(t, sig.HasAttribute(fingerprint.Location),
		"Location should NOT be stable when each path redirects to different target")

	// /api → /api/ should MATCH because signature only has StatusCode (301)
	// This is expected behavior - all 301s are considered soft-404
	apiURL, _ := url.Parse(server.URL + "/api")
	req, _ := http.NewRequest("GET", apiURL.String(), nil)

	resp, err := client.Get(apiURL.String())
	require.NoError(t, err)

	rc := createTestResponseChain(resp)
	defer rc.Close()

	found, err := analyzer.Analyze(context.Background(), req, rc)
	require.NoError(t, err)

	// When Location is unstable, ALL 301s match → soft-404
	assert.False(t, found,
		"When Location is unstable, all 301 redirects should be soft-404 (not found)")
}

// TestAnalyzer_200WithBody verifies that 200 OK with matching body is soft-404.
func TestAnalyzer_200WithBody(t *testing.T) {
	body := "<html><body>Page not found - but returns 200</body></html>"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	learner := fingerprint.NewLearner(nil, nil) // default client OK for non-redirect
	learner.SetDelay(0)
	cache := fingerprint.NewCache(learner)
	comparator := fingerprint.NewComparator(cache, learner)
	analyzer := NewAnalyzer(comparator)

	baseURL, _ := url.Parse(server.URL + "/")

	// Learn signature
	rootKey := fingerprint.CacheKey{Host: baseURL.Host, Extension: ""}
	_, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Test new path
	testURL, _ := url.Parse(server.URL + "/random")
	req, _ := http.NewRequest("GET", testURL.String(), nil)

	resp, err := http.Get(testURL.String())
	require.NoError(t, err)

	rc := createTestResponseChain(resp)
	defer rc.Close()

	found, err := analyzer.Analyze(context.Background(), req, rc)
	require.NoError(t, err)

	assert.False(t, found,
		"200 OK with matching soft-404 signature should return false (not found)")
}
