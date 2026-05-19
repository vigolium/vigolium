package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLearner(t *testing.T) {
	learner := NewLearner(nil, nil)
	assert.NotNil(t, learner)
	assert.NotNil(t, learner.client)
	assert.Equal(t, 20*time.Millisecond, learner.delay)
}

func TestLearner_SetDelay(t *testing.T) {
	learner := NewLearner(nil, nil)
	learner.SetDelay(500 * time.Millisecond)
	assert.Equal(t, 500*time.Millisecond, learner.delay)
}

func TestLearner_Learn_Static404(t *testing.T) {
	// Create test server returning static 404 page
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
	<h1>Page Not Found</h1>
	<p>The requested page does not exist.</p>
</body>
</html>`)
	}))
	defer server.Close()

	// Create learner with no delay for testing
	learner := NewLearner(nil, nil)
	learner.SetDelay(0)

	// Learn from server
	baseURL, err := url.Parse(server.URL + "/api/test")
	require.NoError(t, err)

	sig, err := learner.Learn(context.Background(), baseURL)
	require.NoError(t, err)
	assert.NotNil(t, sig)

	// Should have detected stable attributes
	assert.Greater(t, sig.StableAttributeCount(), 3, "should have multiple stable attributes")

	// Critical attributes should be stable
	assert.True(t, sig.HasAttribute(StatusCode), "should have StatusCode")
	assert.True(t, sig.HasAttribute(ContentType), "should have ContentType")
}

func TestLearner_Learn_Dynamic404(t *testing.T) {
	// Create test server with dynamic content (timestamp)
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Etag", "W/\""+time.Now().Format("20060102150405")+"\"") // Dynamic ETag
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
	<h1>Page Not Found</h1>
	<p>Request #`+string(rune(requestCount+48))+` - Timestamp: `+time.Now().Format("2006-01-02 15:04:05")+`</p>
</body>
</html>`)
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(10 * time.Millisecond) // Small delay for testing

	baseURL, err := url.Parse(server.URL + "/test")
	require.NoError(t, err)

	sig, err := learner.Learn(context.Background(), baseURL)
	require.NoError(t, err)
	assert.NotNil(t, sig)

	// Structure should be stable (title, h1, status)
	assert.True(t, sig.HasAttribute(StatusCode), "status should be stable")
	// Content might vary so just check we learned something
	assert.Greater(t, sig.StableAttributeCount(), 2, "should have multiple stable attributes")
}

func TestLearner_LearnFromPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0)

	baseURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	paths := []string{"/test1", "/test2", "/test3"}

	sig, err := learner.LearnFromPaths(context.Background(), baseURL, paths)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.Greater(t, sig.StableAttributeCount(), 0)
}

func TestLearner_LearnFromPaths_TooFew(t *testing.T) {
	learner := NewLearner(nil, nil)
	baseURL, _ := url.Parse("http://example.com")

	_, err := learner.LearnFromPaths(context.Background(), baseURL, []string{"/test1", "/test2"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "need at least 3 paths")
}

func TestLearner_Learn_NilURL(t *testing.T) {
	learner := NewLearner(nil, nil)
	_, err := learner.Learn(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestLearner_Learn_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(404)
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	baseURL, _ := url.Parse(server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := learner.Learn(ctx, baseURL)
	assert.Error(t, err)
}

func TestLearner_ValidateSignature(t *testing.T) {
	learner := NewLearner(nil, nil)

	tests := []struct {
		name      string
		sig       *Signature
		expectErr bool
	}{
		{
			name:      "nil_signature",
			sig:       nil,
			expectErr: true,
		},
		{
			name: "single_status_code_is_valid",
			sig: &Signature{
				stable: map[Attribute]uint32{
					StatusCode: 404,
				},
			},
			// Only StatusCode is required - stable attribute count check is disabled
			// This is intentional: redirect signatures may only have StatusCode + Location
			expectErr: false,
		},
		{
			name: "missing_status_code",
			sig: &Signature{
				stable: map[Attribute]uint32{
					ContentType: HashString("text/html"),
					PageTitle:   HashString("404"),
					TagNames:    123,
					DivIDs:      456,
					CSSClasses:  789,
				},
			},
			expectErr: true,
		},
		{
			name: "valid_signature",
			sig: &Signature{
				stable: map[Attribute]uint32{
					StatusCode:  404,
					ContentType: HashString("text/html"),
					PageTitle:   HashString("404"),
					TagNames:    123,
					DivIDs:      456,
					CSSClasses:  789,
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := learner.ValidateSignature(tt.sig)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLearner_LearnWithValidation(t *testing.T) {
	// Server with enough stable attributes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
	<div id="error" class="error-page">
		<h1>Not Found</h1>
		<p>The page does not exist</p>
		<a href="/">Home</a>
	</div>
</body>
</html>`)
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0)

	baseURL, _ := url.Parse(server.URL + "/test")

	sig, err := learner.LearnWithValidation(context.Background(), baseURL)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.GreaterOrEqual(t, sig.StableAttributeCount(), 5)
}

func TestLearner_RequestAndExtract_NonHTML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error": "not found"}`)
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	testURL, _ := url.Parse(server.URL + "/api/test")

	sample, err := learner.RequestAndExtract(context.Background(), testURL)
	require.NoError(t, err)
	assert.NotNil(t, sample)

	// Should have status and content but not HTML attributes
	assert.True(t, sample.HasAttribute(StatusCode))
	assert.False(t, sample.HasAttribute(PageTitle))
}

func TestLearner_Delay_Behavior(t *testing.T) {
	requestTimes := make([]time.Time, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestTimes = append(requestTimes, time.Now())
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "<html><body>404</body></html>")
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(100 * time.Millisecond)

	baseURL, _ := url.Parse(server.URL)

	_, err := learner.Learn(context.Background(), baseURL)
	require.NoError(t, err)

	// Should have 4 requests (GenerateRandomPaths returns 4 paths)
	assert.Len(t, requestTimes, 4)

	// Check delay between requests
	if len(requestTimes) >= 4 {
		delay1 := requestTimes[1].Sub(requestTimes[0])
		delay2 := requestTimes[2].Sub(requestTimes[1])
		delay3 := requestTimes[3].Sub(requestTimes[2])

		assert.GreaterOrEqual(t, delay1.Milliseconds(), int64(90), "should have delay between request 1 and 2")
		assert.GreaterOrEqual(t, delay2.Milliseconds(), int64(90), "should have delay between request 2 and 3")
		assert.GreaterOrEqual(t, delay3.Milliseconds(), int64(90), "should have delay between request 3 and 4")
	}
}

func BenchmarkLearner_Learn(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `
<!DOCTYPE html>
<html>
<head><title>404</title></head>
<body>
	<div class="error">
		<h1>Not Found</h1>
		<p>Error</p>
	</div>
</body>
</html>`)
	}))
	defer server.Close()

	learner := NewLearner(nil, nil)
	learner.SetDelay(0) // No delay for benchmarking

	baseURL, _ := url.Parse(server.URL)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = learner.Learn(context.Background(), baseURL)
	}
}
