package fingerprint

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/deparos/html"
	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

func TestNewSample_StatusCode(t *testing.T) {
	resp := createTestResponse(404, nil, nil, "")
	sample, err := newSampleInternal(resp, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, uint32(404), sample.GetHash(StatusCode))
	assert.True(t, sample.HasAttribute(StatusCode))
}

func TestNewSample_Headers(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Type", "text/html; charset=utf-8")
	headers.Set("Etag", "W/\"abc123\"")
	headers.Set("Last-Modified", "Mon, 15 Nov 2024 10:00:00 GMT")
	headers.Set("Content-Length", "1234")
	headers.Set("Location", "https://example.com/redirect")
	headers.Set("Content-Location", "/resource")
	headers.Add("Set-Cookie", "session_id=abc")
	headers.Add("Set-Cookie", "csrf_token=xyz")

	resp := createTestResponse(200, headers, nil, "")
	sample, err := newSampleInternal(resp, nil, nil)

	require.NoError(t, err)

	// Content-Type (without charset)
	assert.True(t, sample.HasAttribute(ContentType))
	assert.Equal(t, HashString("text/html"), sample.GetHash(ContentType))

	// ETag
	assert.True(t, sample.HasAttribute(ETagHeader))
	assert.NotZero(t, sample.GetHash(ETagHeader))

	// Last-Modified
	assert.True(t, sample.HasAttribute(LastModifiedHeader))
	assert.NotZero(t, sample.GetHash(LastModifiedHeader))

	// Content-Length
	assert.True(t, sample.HasAttribute(ContentLength))
	assert.Equal(t, uint32(1234), sample.GetHash(ContentLength))

	// Location
	assert.True(t, sample.HasAttribute(Location))
	assert.NotZero(t, sample.GetHash(Location))

	// Content-Location
	assert.True(t, sample.HasAttribute(ContentLocation))
	assert.NotZero(t, sample.GetHash(ContentLocation))

	// Cookies
	assert.True(t, sample.HasAttribute(CookieNames))
	assert.NotZero(t, sample.GetHash(CookieNames))
}

func TestNewSample_HTML(t *testing.T) {
	htmlContent := `
<!DOCTYPE html>
<html>
<head>
	<title>Test Page</title>
</head>
<body>
	<div id="main" class="container">
		<h1>404 Not Found</h1>
		<p class="error-message">Page not found</p>
		<a href="/">Home</a>
		<!-- This is a comment -->
		<form>
			<input type="text" name="search">
			<input type="submit" value="Search">
			<button type="submit">Go</button>
		</form>
	</div>
</body>
</html>`

	parser := html.NewParser()
	htmlParsed, err := parser.Parse(strings.NewReader(htmlContent))
	require.NoError(t, err)

	resp := createTestResponse(404, nil, nil, "")
	sample, err := newSampleInternal(resp, htmlParsed, []byte(htmlContent))
	require.NoError(t, err)

	// Page title
	assert.True(t, sample.HasAttribute(PageTitle))
	assert.Equal(t, HashString("Test Page"), sample.GetHash(PageTitle))

	// Tag names
	assert.True(t, sample.HasAttribute(TagNames))
	assert.NotZero(t, sample.GetHash(TagNames))

	// Tag IDs
	assert.True(t, sample.HasAttribute(TagIDs))
	assert.NotZero(t, sample.GetHash(TagIDs))

	// Div IDs
	assert.True(t, sample.HasAttribute(DivIDs))
	assert.NotZero(t, sample.GetHash(DivIDs))

	// CSS Classes
	assert.True(t, sample.HasAttribute(CSSClasses))
	assert.NotZero(t, sample.GetHash(CSSClasses))

	// Header tags
	assert.True(t, sample.HasAttribute(FirstHeaderTag))
	assert.Equal(t, HashString("404 Not Found"), sample.GetHash(FirstHeaderTag))
	assert.True(t, sample.HasAttribute(HeaderTags))
	assert.NotZero(t, sample.GetHash(HeaderTags))

	// Comments
	assert.True(t, sample.HasAttribute(Comments))
	assert.NotZero(t, sample.GetHash(Comments))

	// Anchor labels
	assert.True(t, sample.HasAttribute(AnchorLabels))
	assert.NotZero(t, sample.GetHash(AnchorLabels))

	// Outbound links
	assert.True(t, sample.HasAttribute(OutboundEdgeCount))
	assert.Equal(t, uint32(1), sample.GetHash(OutboundEdgeCount))

	// Form inputs
	assert.True(t, sample.HasAttribute(InputSubmitLabels))
	assert.NotZero(t, sample.GetHash(InputSubmitLabels))

	assert.True(t, sample.HasAttribute(ButtonSubmitLabels))
	assert.NotZero(t, sample.GetHash(ButtonSubmitLabels))

	assert.True(t, sample.HasAttribute(NonHiddenFormInputTypes))
	assert.NotZero(t, sample.GetHash(NonHiddenFormInputTypes))

	// Content
	assert.True(t, sample.HasAttribute(VisibleText))
	assert.NotZero(t, sample.GetHash(VisibleText))

	assert.True(t, sample.HasAttribute(WordCount))
	assert.Greater(t, sample.GetHash(WordCount), uint32(0))

	assert.True(t, sample.HasAttribute(LineCount))
	assert.Greater(t, sample.GetHash(LineCount), uint32(0))
}

func TestNewSample_Content(t *testing.T) {
	body := []byte("This is test content with some words.")

	resp := createTestResponse(200, nil, nil, "")
	sample, err := newSampleInternal(resp, nil, body)
	require.NoError(t, err)

	// Body content
	assert.True(t, sample.HasAttribute(BodyContent))
	assert.Equal(t, HashBytes(body), sample.GetHash(BodyContent))

	// Initial content
	assert.True(t, sample.HasAttribute(InitialContent))
	assert.NotZero(t, sample.GetHash(InitialContent))

	// Limited content
	assert.True(t, sample.HasAttribute(LimitedBodyContent))
	assert.NotZero(t, sample.GetHash(LimitedBodyContent))
}

func TestNewSample_EmptyResponse(t *testing.T) {
	resp := createTestResponse(200, nil, nil, "")
	sample, err := newSampleInternal(resp, nil, nil)

	require.NoError(t, err)
	assert.True(t, sample.HasAttribute(StatusCode))
	assert.Equal(t, uint32(200), sample.GetHash(StatusCode))
}

func TestNewSample_AllAttributes(t *testing.T) {
	// Create a comprehensive response with all possible attributes
	headers := http.Header{
		"Content-Type":     []string{"text/html; charset=utf-8"},
		"ETag":             []string{"W/\"abc123\""},
		"Last-Modified":    []string{"Mon, 15 Nov 2024 10:00:00 GMT"},
		"Content-Length":   []string{"500"},
		"Location":         []string{"/redirect"},
		"Content-Location": []string{"/actual"},
		"Set-Cookie":       []string{"session=xyz"},
	}

	htmlContent := `
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
	<div id="main" class="container">
		<h1>Header</h1>
		<!-- Comment -->
		<a href="/link">Link</a>
		<form>
			<input type="text">
			<input type="submit" value="Submit">
		</form>
	</div>
</body>
</html>`

	parser := html.NewParser()
	htmlParsed, err := parser.Parse(strings.NewReader(htmlContent))
	require.NoError(t, err)

	resp := createTestResponse(200, headers, nil, htmlContent)
	sample, err := newSampleInternal(resp, htmlParsed, []byte(htmlContent))
	require.NoError(t, err)

	// Verify we have many attributes extracted
	allAttrs := sample.AllAttributes()
	assert.Greater(t, len(allAttrs), 15, "should extract many attributes")

	// Verify critical attributes
	assert.True(t, sample.HasAttribute(StatusCode))
	assert.True(t, sample.HasAttribute(ContentType))
}

func TestSample_Consistency(t *testing.T) {
	// Same input should produce same hashes
	htmlContent := `<html><head><title>Test</title></head><body><p>Content</p></body></html>`

	parser := html.NewParser()
	htmlParsed1, err := parser.Parse(strings.NewReader(htmlContent))
	require.NoError(t, err)
	htmlParsed2, err := parser.Parse(strings.NewReader(htmlContent))
	require.NoError(t, err)

	resp1 := createTestResponse(200, nil, nil, htmlContent)
	resp2 := createTestResponse(200, nil, nil, htmlContent)

	sample1, err := newSampleInternal(resp1, htmlParsed1, []byte(htmlContent))
	require.NoError(t, err)

	sample2, err := newSampleInternal(resp2, htmlParsed2, []byte(htmlContent))
	require.NoError(t, err)

	// All attributes should match
	for attr := Attribute(1); attr <= 32; attr++ {
		if sample1.HasAttribute(attr) {
			assert.Equal(t, sample1.GetHash(attr), sample2.GetHash(attr),
				"attribute %s should have consistent hash", attr.String())
		}
	}
}

func TestSample_DifferentContent(t *testing.T) {
	// Different content should produce different hashes
	html1 := `<html><body><h1>Page 1</h1></body></html>`
	html2 := `<html><body><h1>Page 2</h1></body></html>`

	parser := html.NewParser()
	htmlParsed1, _ := parser.Parse(strings.NewReader(html1))
	htmlParsed2, _ := parser.Parse(strings.NewReader(html2))

	resp1 := createTestResponse(200, nil, nil, html1)
	resp2 := createTestResponse(200, nil, nil, html2)

	sample1, _ := newSampleInternal(resp1, htmlParsed1, []byte(html1))
	sample2, _ := newSampleInternal(resp2, htmlParsed2, []byte(html2))

	// Header content should differ
	assert.NotEqual(t, sample1.GetHash(FirstHeaderTag), sample2.GetHash(FirstHeaderTag))

	// Body content should differ
	assert.NotEqual(t, sample1.GetHash(BodyContent), sample2.GetHash(BodyContent))
}

func TestNewSampleFromRC(t *testing.T) {
	htmlContent := `
<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body><h1>Welcome</h1><p>Content here</p></body>
</html>`

	headers := http.Header{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}

	resp := createTestResponse(200, headers, nil, htmlContent)
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	defer rc.Close()

	sample, err := NewSampleFromRC(rc)
	require.NoError(t, err)
	assert.NotNil(t, sample)

	// Should have extracted HTML attributes
	assert.True(t, sample.HasAttribute(PageTitle))
	assert.True(t, sample.HasAttribute(FirstHeaderTag))
	assert.True(t, sample.HasAttribute(BodyContent))
}

func TestNewSampleFromRC_NonHTML(t *testing.T) {
	jsonContent := `{"message": "not found"}`

	headers := http.Header{
		"Content-Type": []string{"application/json"},
	}

	resp := createTestResponse(404, headers, nil, jsonContent)
	rc := responsechain.NewResponseChain(resp, 0)
	_ = rc.Fill()
	defer rc.Close()

	sample, err := NewSampleFromRC(rc)
	require.NoError(t, err)
	assert.NotNil(t, sample)

	// Should have status and content but no HTML attributes
	assert.True(t, sample.HasAttribute(StatusCode))
	assert.True(t, sample.HasAttribute(BodyContent))
	assert.False(t, sample.HasAttribute(PageTitle))
}

func TestSample_Debug(t *testing.T) {
	resp := createTestResponse(404, nil, nil, "")
	sample, err := newSampleInternal(resp, nil, nil)

	require.NoError(t, err)
	debug := sample.Debug()
	assert.Contains(t, debug, "404")
	assert.Contains(t, debug, "/test")
}

// Helper function to create test HTTP responses
func createTestResponse(statusCode int, headers http.Header, body io.ReadCloser, bodyStr string) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}

	if body == nil && bodyStr != "" {
		body = io.NopCloser(bytes.NewBufferString(bodyStr))
	} else if body == nil {
		body = io.NopCloser(bytes.NewBufferString(""))
	}

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/test",
		},
	}

	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     headers,
		Body:       body,
		Request:    req,
	}
}

func BenchmarkNewSample_Full(b *testing.B) {
	htmlContent := `
<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
	<div id="main" class="container">
		<h1>Header</h1>
		<p>Content</p>
		<a href="/link">Link</a>
	</div>
</body>
</html>`

	parser := html.NewParser()
	htmlParsed, _ := parser.Parse(strings.NewReader(htmlContent))

	headers := http.Header{
		"Content-Type": []string{"text/html"},
		"ETag":         []string{"W/\"abc\""},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := createTestResponse(200, headers, nil, htmlContent)
		_, _ = newSampleInternal(resp, htmlParsed, []byte(htmlContent))
	}
}

func BenchmarkNewSample_HeadersOnly(b *testing.B) {
	headers := http.Header{
		"Content-Type":   []string{"application/json"},
		"ETag":           []string{"W/\"abc123\""},
		"Last-Modified":  []string{"Mon, 15 Nov 2024 10:00:00 GMT"},
		"Content-Length": []string{"1234"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := createTestResponse(404, headers, nil, "")
		_, _ = newSampleInternal(resp, nil, nil)
	}
}
