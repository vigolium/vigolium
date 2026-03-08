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

	"github.com/vigolium/vigolium/pkg/deparos/html"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// ====================================================================================
// REGRESSION TESTS: Empty Body HTML Parsing Bug
// ====================================================================================
//
// BUG: Go's html.Parse("") creates valid <html><head><body> structure even for empty input.
// This caused fingerprint mismatch for 307 redirects with empty body:
//
// 1. Learning phase: Body parsed even when empty → phantom tag_names/line_count attributes
// 2. Discovery phase: Samples don't have these phantom attributes → no match → soft-404 not detected
//
// FIX: Skip HTML parsing when len(body) == 0
// ====================================================================================

// TestEmptyBodyNoHTMLAttributes verifies that empty body with HTML content-type
// does NOT create phantom HTML attributes (tag_names, line_count, etc.)
func TestEmptyBodyNoHTMLAttributes(t *testing.T) {
	headers := http.Header{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}

	resp := &http.Response{
		StatusCode: 307,
		Status:     "Temporary Redirect",
		Header:     headers,
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		},
	}

	// Empty body - should NOT parse HTML
	sample, err := newSampleInternal(resp, nil, []byte{})
	require.NoError(t, err)

	// StatusCode and ContentType should be present
	assert.True(t, sample.HasAttribute(StatusCode), "should have StatusCode")
	assert.True(t, sample.HasAttribute(ContentType), "should have ContentType")

	// HTML attributes should NOT be present (no phantom tags from empty body)
	assert.False(t, sample.HasAttribute(TagNames), "TagNames should NOT be present for empty body")
	assert.False(t, sample.HasAttribute(LineCount), "LineCount should NOT be present for empty body")
	assert.False(t, sample.HasAttribute(PageTitle), "PageTitle should NOT be present for empty body")
	assert.False(t, sample.HasAttribute(TagIDs), "TagIDs should NOT be present for empty body")
	assert.False(t, sample.HasAttribute(DivIDs), "DivIDs should NOT be present for empty body")
	assert.False(t, sample.HasAttribute(CSSClasses), "CSSClasses should NOT be present for empty body")
}

// TestNewSampleFromRC_EmptyBodyHTML verifies NewSampleFromRC handles empty body correctly
func TestNewSampleFromRC_EmptyBodyHTML(t *testing.T) {
	headers := http.Header{
		"Content-Type": []string{"text/html"},
	}

	resp := &http.Response{
		StatusCode: 307,
		Status:     "Temporary Redirect",
		Header:     headers,
		Body:       io.NopCloser(bytes.NewBufferString("")), // Empty body
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/redirect"},
		},
	}

	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	defer rc.Close()

	sample, err := NewSampleFromRC(rc)
	require.NoError(t, err)

	// StatusCode should be present
	assert.True(t, sample.HasAttribute(StatusCode))
	assert.Equal(t, uint32(307), sample.GetHash(StatusCode))

	// HTML attributes should NOT be present
	assert.False(t, sample.HasAttribute(TagNames), "TagNames should NOT be present")
	assert.False(t, sample.HasAttribute(LineCount), "LineCount should NOT be present")
}

// TestLearner_307RedirectEmptyBody tests that learner handles 307 redirects with empty body correctly
func TestLearner_307RedirectEmptyBody(t *testing.T) {
	// Simulate gcas.stryker.com behavior: 307 redirect with empty body and dynamic Location
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Location", "https://example.com"+r.URL.Path) // Dynamic per-path
		w.WriteHeader(307)
		// Empty body - no content written
	}))
	defer server.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	learner := NewLearner(client, nil)
	learner.SetDelay(0)

	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)

	sig, err := learner.Learn(context.Background(), baseURL)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Signature should NOT have HTML attributes (no phantom tags from empty body)
	assert.False(t, sig.HasAttribute(TagNames), "Signature should NOT have TagNames for empty body redirect")
	assert.False(t, sig.HasAttribute(LineCount), "Signature should NOT have LineCount for empty body redirect")

	// Should have StatusCode and ContentType
	assert.True(t, sig.HasAttribute(StatusCode), "Signature should have StatusCode")
	assert.True(t, sig.HasAttribute(ContentType), "Signature should have ContentType")

	t.Logf("Signature stable attributes: %v", sig.GetStableAttributes())
}

// TestSignatureMatchConsistency_EmptyBody tests that signature matching is consistent for empty body
func TestSignatureMatchConsistency_EmptyBody(t *testing.T) {
	// Simulate 307 redirect with empty body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Location", "https://example.com"+r.URL.Path)
		w.WriteHeader(307)
		// Empty body
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

	// Learn signature
	rootKey := CacheKey{Host: baseURL.Host, Path: "/", Extension: ""}
	sig, err := cache.LearnAndCache(context.Background(), rootKey, baseURL)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Test paths - all should match since they all get same 307 empty body response
	testPaths := []string{"/admin", "/backup", "/config", "/random123"}

	for _, path := range testPaths {
		testURL, _ := url.Parse(server.URL + path)
		req, _ := http.NewRequestWithContext(context.Background(), "GET", testURL.String(), nil)
		resp, err := client.Do(req)
		require.NoError(t, err)

		rc := responsechain.NewResponseChain(resp, 0)
		_ = rc.Fill()

		// Create sample from response
		sample, err := NewSampleFromRC(rc)
		require.NoError(t, err)

		// Cascade should match
		matched := cache.MatchesWithCascade(testURL, sample)
		assert.True(t, matched, "Path %s should match signature (cascade)", path)

		// Compare should return FalsePositive
		result, err := comparator.Compare(context.Background(), req, rc)
		require.NoError(t, err)
		assert.Equal(t, FalsePositive, result, "Path %s should be FalsePositive", path)

		rc.Close()
	}
}

// TestHTMLParseEmptyStringCreatesPhantomTags documents Go's html.Parse behavior
// This test exists to document the bug we're protecting against
func TestHTMLParseEmptyStringCreatesPhantomTags(t *testing.T) {
	parser := html.NewParser()

	// Parse empty string - this creates phantom structure!
	parsed, err := parser.Parse(strings.NewReader(""))
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Document the behavior we're protecting against
	t.Logf("html.Parse(\"\") creates: TagNames=%v, LineCount=%d", parsed.TagNames, parsed.LineCount)

	// html.Parse("") creates html, head, body tags even for empty input
	// This is the BUG we need to protect against
	if len(parsed.TagNames) > 0 {
		t.Logf("WARNING: html.Parse creates phantom tags: %v", parsed.TagNames)
		assert.Contains(t, parsed.TagNames, "html", "Go's html.Parse creates <html> tag for empty input")
		assert.Contains(t, parsed.TagNames, "head", "Go's html.Parse creates <head> tag for empty input")
		assert.Contains(t, parsed.TagNames, "body", "Go's html.Parse creates <body> tag for empty input")
	}
}

// TestLearner_RequestAndExtract_EmptyHTMLBody tests RequestAndExtract with empty HTML body
func TestLearner_RequestAndExtract_EmptyHTMLBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(307)
		// No body written
	}))
	defer server.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	learner := NewLearner(client, nil)
	testURL, _ := url.Parse(server.URL + "/test")

	sample, err := learner.RequestAndExtract(context.Background(), testURL)
	require.NoError(t, err)

	// Should have status code
	assert.True(t, sample.HasAttribute(StatusCode))
	assert.Equal(t, uint32(307), sample.GetHash(StatusCode))

	// Should NOT have phantom HTML attributes
	assert.False(t, sample.HasAttribute(TagNames), "Should NOT have TagNames for empty body")
	assert.False(t, sample.HasAttribute(LineCount), "Should NOT have LineCount for empty body")
}

// TestCacheMatchConsistency_EmptyBodyRedirect tests cache matching consistency
func TestCacheMatchConsistency_EmptyBodyRedirect(t *testing.T) {
	// Create a signature from 307 redirect responses with empty body
	samples := make([]*Sample, 3)

	for i := 0; i < 3; i++ {
		headers := http.Header{
			"Content-Type":   []string{"text/html"},
			"Content-Length": []string{"0"},
			"Location":       []string{"https://example.com/path" + string(rune('0'+i))}, // Different locations
		}

		resp := &http.Response{
			StatusCode: 307,
			Status:     "Temporary Redirect",
			Header:     headers,
			Body:       io.NopCloser(bytes.NewBufferString("")),
			Request: &http.Request{
				Method: "GET",
				URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/test" + string(rune('0'+i))},
			},
		}

		sample, err := newSampleInternal(resp, nil, []byte{})
		require.NoError(t, err)
		samples[i] = sample
	}

	// Create signature
	sig, err := NewSignature(samples)
	require.NoError(t, err)

	t.Logf("Signature: %s", sig.DebugString())
	t.Logf("Stable attributes: %v", sig.GetStableAttributes())

	// Location should be unstable (different per request)
	// StatusCode, ContentType, ContentLength should be stable
	assert.True(t, sig.HasAttribute(StatusCode))
	assert.True(t, sig.HasAttribute(ContentType))
	assert.True(t, sig.HasAttribute(ContentLength))

	// Verify NO phantom HTML attributes
	assert.False(t, sig.HasAttribute(TagNames), "Should NOT have TagNames")
	assert.False(t, sig.HasAttribute(LineCount), "Should NOT have LineCount")

	// Test matching - new sample with same pattern should match
	newResp := &http.Response{
		StatusCode: 307,
		Status:     "Temporary Redirect",
		Header: http.Header{
			"Content-Type":   []string{"text/html"},
			"Content-Length": []string{"0"},
			"Location":       []string{"https://example.com/different"},
		},
		Body: io.NopCloser(bytes.NewBufferString("")),
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/newpath"},
		},
	}

	newSample, err := newSampleInternal(newResp, nil, []byte{})
	require.NoError(t, err)

	// Should match signature
	assert.True(t, sig.Matches(newSample), "New sample should match signature")
}
