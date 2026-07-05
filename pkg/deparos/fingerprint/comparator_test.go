package fingerprint

import (
	"bytes"
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

// createTestResponseChain creates a ResponseChain for testing from status, headers, and body.
func createTestResponseChain(statusCode int, headers http.Header, body string) *responsechain.ResponseChain {
	if headers == nil {
		headers = http.Header{}
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

func TestNewComparator(t *testing.T) {
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	assert.NotNil(t, comp)
	assert.NotNil(t, comp.cache)
	assert.NotNil(t, comp.learner)
}

func TestMatchResult_String(t *testing.T) {
	tests := []struct {
		result   MatchResult
		expected string
	}{
		{Unknown, "Unknown"},
		{TruePositive, "TruePositive"},
		{FalsePositive, "FalsePositive"},
		{MatchResult(99), "MatchResult(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.String())
		})
	}
}

func TestComparator_Compare_NoSignatures_404(t *testing.T) {
	// Test: HTTP 404 with no signatures → FalsePositive
	// Compare() now handles Unknown internally by calling CheckWildcardWithValidation()
	// HTTP 404 is always FalsePositive regardless of signatures (quick exit path)
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	req := createTestHTTPRequest(t, "GET", "https://example.com/test", nil)
	rc := createTestResponseChain(404, http.Header{"Content-Type": []string{"text/html"}}, "<html><body>404</body></html>")
	defer rc.Close()

	result, err := comp.Compare(context.Background(), req, rc)
	require.NoError(t, err)
	assert.Equal(t, FalsePositive, result, "HTTP 404 should return FalsePositive")
}

func TestComparator_Compare_MatchesSignature(t *testing.T) {
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	// Add signature to cache
	key := CacheKey{Host: "example.com", Path: "/", Extension: ""}
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	cache.Add(key, sig)

	// Create matching request/response
	req := createTestHTTPRequest(t, "GET", "https://example.com/test", nil)
	rc := createTestResponseChain(404, http.Header{"Content-Type": []string{"text/html"}}, "")
	defer rc.Close()

	result, err := comp.Compare(context.Background(), req, rc)
	require.NoError(t, err)
	assert.Equal(t, FalsePositive, result, "should match 404 signature")
}

func TestComparator_Compare_DoesNotMatch(t *testing.T) {
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	// Add 404 signature to cache
	key := CacheKey{Host: "example.com", Path: "/", Extension: ""}
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	cache.Add(key, sig)

	// Create non-matching response (200 instead of 404)
	req := createTestHTTPRequest(t, "GET", "https://example.com/test", nil)
	rc := createTestResponseChain(200, http.Header{"Content-Type": []string{"text/html"}}, "")
	defer rc.Close()

	result, err := comp.Compare(context.Background(), req, rc)
	require.NoError(t, err)
	assert.Equal(t, TruePositive, result, "should not match different status")
}

func TestComparator_Compare_NilRequest(t *testing.T) {
	comp := NewComparator(nil, nil)
	rc := createTestResponseChain(200, http.Header{}, "")
	defer rc.Close()

	_, err := comp.Compare(context.Background(), nil, rc)
	assert.Error(t, err)
}

func TestComparator_Compare_NilResponseChain(t *testing.T) {
	comp := NewComparator(nil, nil)
	req := createTestHTTPRequest(t, "GET", "https://example.com/test", nil)

	_, err := comp.Compare(context.Background(), req, nil)
	assert.Error(t, err)
}

func TestComparator_CompareWithLearning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comp := NewComparator(cache, learner)

	req := createTestHTTPRequest(t, "GET", server.URL+"/test", nil)
	rc := createTestResponseChain(404, http.Header{"Content-Type": []string{"text/html"}}, "<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	defer rc.Close()

	// First call should learn
	result, err := comp.CompareWithLearning(context.Background(), req, rc)
	require.NoError(t, err)
	// Result depends on learning success
	assert.NotEqual(t, Unknown, result)
}

func TestComparator_IsSoft404(t *testing.T) {
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	// Add 404 signature
	key := CacheKey{Host: "example.com", Path: "/", Extension: ""}
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	cache.Add(key, sig)

	// Test matching (soft 404)
	req := createTestHTTPRequest(t, "GET", "https://example.com/test", nil)
	rc := createTestResponseChain(404, http.Header{"Content-Type": []string{"text/html"}}, "")
	defer rc.Close()

	isSoft404, err := comp.IsSoft404(context.Background(), req, rc)
	require.NoError(t, err)
	assert.True(t, isSoft404)

	// Test non-matching (real resource)
	rc2 := createTestResponseChain(200, http.Header{"Content-Type": []string{"text/html"}}, "")
	defer rc2.Close()

	isSoft404, err = comp.IsSoft404(context.Background(), req, rc2)
	require.NoError(t, err)
	assert.False(t, isSoft404)
}

func TestComparator_LearnIfNeeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comp := NewComparator(cache, learner)

	testURL, _ := url.Parse(server.URL + "/test")

	// First call should learn
	err := comp.LearnIfNeeded(context.Background(), testURL)
	require.NoError(t, err)

	// Cache should have signature now
	key := ExtractCacheKey(testURL)
	sigs, ok := cache.Get(key)
	assert.True(t, ok)
	assert.NotEmpty(t, sigs)

	// Second call should not learn again
	err = comp.LearnIfNeeded(context.Background(), testURL)
	require.NoError(t, err)

	// Should still have same signatures
	sigs2, ok := cache.Get(key)
	assert.True(t, ok)
	assert.Len(t, sigs2, len(sigs))
}

func TestComparator_ValidateDynamic(t *testing.T) {
	// Create server that returns different content for different paths
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/real-resource" {
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "<html><body>Real content</body></html>")
		} else {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, "<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
		}
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0)
	cache := NewCache(learner)
	comp := NewComparator(cache, learner)

	// Learn 404 signature first
	testURL, _ := url.Parse(server.URL + "/nonexistent")
	err := comp.LearnIfNeeded(context.Background(), testURL)
	require.NoError(t, err)

	// Create sample from 404 response
	req := createTestHTTPRequest(t, "GET", server.URL+"/test404", nil)
	resp := &http.Response{
		StatusCode: 404,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewBufferString("<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")),
		Request:    req,
	}

	sample, err := newSampleInternal(resp, nil, []byte("<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>"))
	require.NoError(t, err)

	// Dynamic validation
	result, err := comp.ValidateDynamic(context.Background(), req, sample)
	require.NoError(t, err)

	// Result should indicate 404 pattern or real resource
	assert.NotEqual(t, Unknown, result)
}

func TestComparator_ValidateDynamic_NilRequest(t *testing.T) {
	comp := NewComparator(nil, nil)
	_, err := comp.ValidateDynamic(context.Background(), nil, &Sample{})
	assert.Error(t, err)
}

// Helper function to create test HTTP request
func createTestHTTPRequest(t *testing.T, method, urlStr string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, urlStr, body)
	require.NoError(t, err)
	return req
}

// TestComparator_PrefixRoutedEmptyBody_NotWildcard is a regression test for a real
// endpoint dropped by naive wildcard validation.
//
// Scenario (mirrors login.aspciamqalogin.roche.com's SAP Gigya gateway): the origin
// routes on the last-segment PREFIX — any path whose last segment starts with a real
// route name ("metrics") returns 200 with an empty body, while paths that break the
// prefix return 404. /metrics is a genuine Prometheus endpoint that returns an empty
// body on the cluster backends without the exporter.
//
// Before the fix the Suffix ("metrics{rand}") and Extension ("metrics.{rand}")
// wildcard probes preserve the prefix and return 200, so the OR-logic classified
// /metrics as a wildcard false-positive and dropped it. After the fix only
// prefix-BREAKING probes (Prefix/Middle) count toward wildcard detection; those 404
// here, so /metrics is correctly TruePositive.
func TestComparator_PrefixRoutedEmptyBody_NotWildcard(t *testing.T) {
	lastSegHasPrefix := func(rawPath, prefix string) bool {
		seg := rawPath
		if i := strings.LastIndex(seg, "/"); i >= 0 {
			seg = seg[i+1:]
		}
		return strings.HasPrefix(seg, prefix)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route on the last-segment prefix, like the real gateway: "metrics*" is a
		// registered route that answers an empty 200 on this backend; everything
		// that breaks the prefix is a genuine 404.
		if lastSegHasPrefix(r.URL.EscapedPath(), "metrics") {
			w.WriteHeader(http.StatusOK) // empty body, no content-type
			return
		}
		w.WriteHeader(http.StatusNotFound)
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

	// Learn the root ("") baseline from random paths (all 404 here).
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	_, err = cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)

	// Evaluate /metrics — a real route that returns an empty 200.
	metricsURL := server.URL + "/metrics"
	req := createTestHTTPRequest(t, "GET", metricsURL, nil)
	resp, err := client.Get(metricsURL)
	require.NoError(t, err)
	rc := responsechain.NewResponseChain(resp, 0)
	require.NoError(t, rc.Fill())
	defer rc.Close()

	result, err := comparator.Compare(context.Background(), req, rc)
	require.NoError(t, err)
	assert.Equal(t, TruePositive, result,
		"/metrics behind a prefix-router must be TruePositive, not dropped as a wildcard")
}

func BenchmarkComparator_Compare(b *testing.B) {
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	// Add signature
	key := CacheKey{Host: "example.com", Path: "/", Extension: ""}
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	cache.Add(key, sig)

	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	rc := createTestResponseChain(404, http.Header{"Content-Type": []string{"text/html"}}, "")
	defer rc.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = comp.Compare(context.Background(), req, rc)
	}
}

func BenchmarkComparator_IsSoft404(b *testing.B) {
	cache := NewCache(nil)
	learner := NewLearner(nil, nil)
	comp := NewComparator(cache, learner)

	key := CacheKey{Host: "example.com", Path: "/", Extension: ""}
	sig := &Signature{
		stable: map[Attribute]uint32{
			StatusCode:  404,
			ContentType: HashString("text/html"),
		},
	}
	cache.Add(key, sig)

	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	rc := createTestResponseChain(404, http.Header{"Content-Type": []string{"text/html"}}, "")
	defer rc.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = comp.IsSoft404(context.Background(), req, rc)
	}
}
