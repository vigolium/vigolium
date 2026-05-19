package spider

import (
	"net/url"
	"sync"
	"testing"

	"golang.org/x/net/html"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPResponse_ParseHTML(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectError bool
	}{
		{
			name: "valid HTML",
			body: `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body><h1>Hello</h1></body>
</html>`,
			expectError: false,
		},
		{
			name:        "minimal HTML",
			body:        `<html><body>Test</body></html>`,
			expectError: false,
		},
		{
			name:        "HTML fragment",
			body:        `<div><p>Test</p></div>`,
			expectError: false,
		},
		{
			name:        "malformed HTML (still parseable)",
			body:        `<html><body><p>Unclosed paragraph</body></html>`,
			expectError: false,
		},
		{
			name:        "empty body",
			body:        "",
			expectError: false, // html.Parse handles empty input
		},
		{
			name:        "plain text",
			body:        "This is plain text without HTML tags",
			expectError: false, // html.Parse wraps in <html><body>
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse("https://example.com")
			resp := NewHTTPResponse(u, nil, []byte(tt.body), 0)

			err := resp.ParseHTML()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp.HTML)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp.HTML)
			}
		})
	}
}

func TestHTTPResponse_ParseHTML_Caching(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	body := []byte(`<html><body><h1>Test</h1></body></html>`)
	resp := NewHTTPResponse(u, nil, body, 0)

	// First parse
	err1 := resp.ParseHTML()
	require.NoError(t, err1)
	html1 := resp.HTML

	// Second parse (should return cached result)
	err2 := resp.ParseHTML()
	require.NoError(t, err2)
	html2 := resp.HTML

	// Should be the exact same pointer (cached)
	assert.Equal(t, html1, html2, "HTML should be cached")
}

func TestHTTPResponse_ParseHTML_ConcurrentAccess(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	body := []byte(`<html><body><h1>Test</h1></body></html>`)
	resp := NewHTTPResponse(u, nil, body, 0)

	// Parse concurrently from multiple goroutines
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make([]*html.Node, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()
			err := resp.ParseHTML()
			assert.NoError(t, err)
			results[index] = resp.HTML
		}(i)
	}

	wg.Wait()

	// All goroutines should get the same cached HTML pointer
	firstHTML := results[0]
	for i := 1; i < numGoroutines; i++ {
		assert.Equal(t, firstHTML, results[i], "All goroutines should see the same cached HTML")
	}
}

func TestHTTPResponse_ParseHTML_ErrorCaching(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	body := []byte(`<html><body>Test</body></html>`)
	resp := NewHTTPResponse(u, nil, body, 0)

	// Parse twice
	err1 := resp.ParseHTML()
	err2 := resp.ParseHTML()

	// Errors should be the same (cached)
	assert.Equal(t, err1, err2)
}

func TestNewHTTPResponse(t *testing.T) {
	u, _ := url.Parse("https://example.com/api")
	headers := map[string][]string{
		"Content-Type":   {"text/html; charset=utf-8"},
		"Content-Length": {"1234"},
	}
	body := []byte("<html><body>Test</body></html>")
	bodyStart := 100

	resp := NewHTTPResponse(u, headers, body, bodyStart)

	assert.Equal(t, u, resp.URL)
	assert.Equal(t, headers, resp.Headers)
	assert.Equal(t, body, resp.Body)
	assert.Equal(t, bodyStart, resp.BodyStart)
	assert.Nil(t, resp.HTML) // Not parsed yet
}

func BenchmarkHTTPResponse_ParseHTML(b *testing.B) {
	u, _ := url.Parse("https://example.com")
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
	<h1>Test</h1>
	<div>
		<p>This is a test paragraph.</p>
		<ul>
			<li><a href="/page1">Page 1</a></li>
			<li><a href="/page2">Page 2</a></li>
			<li><a href="/page3">Page 3</a></li>
		</ul>
	</div>
</body>
</html>`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := NewHTTPResponse(u, nil, body, 0)
		_ = resp.ParseHTML()
	}
}

func BenchmarkHTTPResponse_ParseHTML_Cached(b *testing.B) {
	u, _ := url.Parse("https://example.com")
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
	<h1>Test</h1>
	<div>
		<p>This is a test paragraph.</p>
	</div>
</body>
</html>`)

	resp := NewHTTPResponse(u, nil, body, 0)
	_ = resp.ParseHTML() // First parse

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = resp.ParseHTML() // Cached access
	}
}

func TestHTTPResponse_ParseHTML_MaxBodySize(t *testing.T) {
	u, _ := url.Parse("https://example.com")

	// Create body that exceeds MaxBodySize (10MB)
	largeBody := make([]byte, MaxBodySize+1)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	resp := NewHTTPResponse(u, nil, largeBody, 0)

	// Should return ErrBodyTooLarge
	err := resp.ParseHTML()
	assert.Error(t, err)
	assert.Equal(t, ErrBodyTooLarge, err)
	assert.Nil(t, resp.HTML)

	// Second call should return cached error
	err2 := resp.ParseHTML()
	assert.Equal(t, err, err2)
}

func TestHTTPResponse_ParseHTML_JustUnderMaxBodySize(t *testing.T) {
	u, _ := url.Parse("https://example.com")

	// Create body just under MaxBodySize
	body := make([]byte, MaxBodySize-100)
	copy(body, []byte("<html><body>"))
	copy(body[len(body)-14:], []byte("</body></html>"))

	resp := NewHTTPResponse(u, nil, body, 0)

	// Should parse successfully
	err := resp.ParseHTML()
	assert.NoError(t, err)
	assert.NotNil(t, resp.HTML)
}
