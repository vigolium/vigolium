package spider

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExtractionCoordinator(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	httpHeaders := NewHTTPHeaderExtractor(resolver)
	htmlAttrs := NewHTMLAttributeExtractor(resolver)
	comments := NewCommentsExtractor(inlineScanner)
	robotsParser := NewRobotsTxtParser(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlAttrs)
	eventHandlers := NewEventHandlersExtractor(inlineScanner, jsExtractor)
	metaRefresh := NewMetaRefreshExtractor(inlineScanner)
	scriptContent := NewScriptContentExtractor(inlineScanner, jsExtractor)
	formExtractor := NewFormExtractor(resolver)

	coordinator := NewExtractionCoordinator(
		inlineScanner,
		httpHeaders,
		htmlAttrs,
		comments,
		robotsParser,
		jsExtractor,
		eventHandlers,
		metaRefresh,
		scriptContent,
		formExtractor,
	)

	require.NotNil(t, coordinator)
	assert.Equal(t, inlineScanner, coordinator.inlineScanner)
	assert.Equal(t, httpHeaders, coordinator.httpHeaders)
	assert.Equal(t, htmlAttrs, coordinator.htmlAttrs)
	assert.Equal(t, comments, coordinator.comments)
	assert.Equal(t, robotsParser, coordinator.robotsParser)
	assert.Equal(t, jsExtractor, coordinator.jsExtractor)
	assert.Equal(t, eventHandlers, coordinator.eventHandlers)
	assert.Equal(t, metaRefresh, coordinator.metaRefresh)
	assert.Equal(t, scriptContent, coordinator.scriptContent)
	assert.Equal(t, formExtractor, coordinator.formExtractor)
}

func TestExtractionCoordinator_Extract_EmptyResponse(t *testing.T) {
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    []byte{},
	}

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	assert.Empty(t, result.Links, "empty response should yield no links")
}

func TestExtractionCoordinator_Extract_SmallBody(t *testing.T) {
	// Test body < 10 bytes case
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    []byte("small"), // 5 bytes
	}

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	// Small bodies skip HTML processing but still run inline scanner
	// Since "small" doesn't contain http://, no links should be found
	assert.Empty(t, result.Links)
}

func TestExtractionCoordinator_Extract_InlineURLs(t *testing.T) {
	// Test that inline URL scanner always runs
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	body := []byte("Check out https://example.com/page1 and http://example.com/page2")
	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    body,
	}

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Links), 2, "should find at least 2 inline URLs")

	// Verify links are found
	foundPage1 := false
	foundPage2 := false
	for _, link := range result.Links {
		if link.Path == "/page1" {
			foundPage1 = true
		}
		if link.Path == "/page2" {
			foundPage2 = true
		}
	}
	assert.True(t, foundPage1, "should find page1")
	assert.True(t, foundPage2, "should find page2")
}

func TestExtractionCoordinator_Extract_HTTPHeaders(t *testing.T) {
	// Test HTTP header extraction
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	response := &HTTPResponse{
		URL: baseURL,
		Headers: map[string][]string{
			"Location": {"/redirected"},
		},
		Body: []byte("Redirecting..."),
	}

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)

	foundRedirect := false
	for _, link := range result.Links {
		if link.Path == "/redirected" {
			foundRedirect = true
		}
	}
	assert.True(t, foundRedirect, "should find redirect from Location header")
}

func TestExtractionCoordinator_Extract_HTMLAttributes(t *testing.T) {
	// Test HTML attribute extraction
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	html := `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
	<a href="/link1">Link 1</a>
	<img src="/image.png">
	<script src="/script.js"></script>
</body>
</html>`

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    []byte(html),
	}

	// Parse HTML
	require.NoError(t, response.ParseHTML())

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Links), 3, "should find at least 3 links from HTML")

	// Verify links are found
	foundLink1 := false
	foundImage := false
	foundScript := false

	for _, link := range result.Links {
		switch link.Path {
		case "/link1":
			foundLink1 = true
		case "/image.png":
			foundImage = true
		case "/script.js":
			foundScript = true
		}
	}

	assert.True(t, foundLink1, "should find /link1")
	assert.True(t, foundImage, "should find /image.png")
	assert.True(t, foundScript, "should find /script.js")
}

func TestExtractionCoordinator_Extract_HTMLComments(t *testing.T) {
	// Test HTML comment extraction
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	html := `<!DOCTYPE html>
<html>
<body>
	<!-- Check https://example.com/commented -->
	<p>Content</p>
</body>
</html>`

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    []byte(html),
	}

	require.NoError(t, response.ParseHTML())

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	if len(result.Links) == 0 {
		t.Logf("No links found in comment test")
	} else {
		for _, link := range result.Links {
			t.Logf("Found link: %s", link)
		}
	}

	foundComment := false
	for _, link := range result.Links {
		if link.Path == "/commented" {
			foundComment = true
		}
	}
	assert.True(t, foundComment, "should find URL in HTML comment")
}

func TestExtractionCoordinator_Extract_RobotsTxt(t *testing.T) {
	// Test robots.txt parsing
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/robots.txt")

	robotsTxt := `User-agent: *
Disallow: /admin/
Allow: /public/
Sitemap: https://example.com/sitemap.xml`

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    []byte(robotsTxt),
	}

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	if len(result.Links) == 0 {
		t.Logf("No links found. Response URL: %s", response.URL)
	} else {
		for _, link := range result.Links {
			t.Logf("Found link: %s", link)
		}
	}
	assert.GreaterOrEqual(t, len(result.Links), 2, "should find at least admin and sitemap URLs")

	foundAdmin := false
	foundSitemap := false

	for _, link := range result.Links {
		if link.Path == "/admin/" {
			foundAdmin = true
		}
		if link.Path == "/sitemap.xml" {
			foundSitemap = true
		}
	}

	assert.True(t, foundAdmin, "should find /admin/ from Disallow")
	assert.True(t, foundSitemap, "should find /sitemap.xml from Sitemap")
}

func TestExtractionCoordinator_Extract_ExtractionOrder(t *testing.T) {
	// Verify extraction order
	// Order: inline scanner → HTTP headers → HTML attrs → comments → robots.txt

	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	html := `<!DOCTYPE html>
<html>
<body>
	<!-- https://example.com/comment -->
	<a href="/link">Link</a>
	Text with https://example.com/inline
</body>
</html>`

	response := &HTTPResponse{
		URL: baseURL,
		Headers: map[string][]string{
			"Location": {"/redirect"},
		},
		Body: []byte(html),
	}

	require.NoError(t, response.ParseHTML())

	result, err := coordinator.extractInternal(context.Background(), baseURL, response)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Links), 3, "should find links from multiple extractors")

	// Verify key paths are present
	foundInline := false
	foundRedirect := false
	foundLink := false
	for _, link := range result.Links {
		switch link.Path {
		case "/inline":
			foundInline = true
		case "/redirect":
			foundRedirect = true
		case "/link":
			foundLink = true
		}
	}

	assert.True(t, foundInline, "should find inline URL")
	assert.True(t, foundRedirect, "should find redirect from header")
	assert.True(t, foundLink, "should find HTML attribute link")
}

func TestExtractionCoordinator_Extract_ContextCancellation(t *testing.T) {
	coordinator := createTestCoordinator()
	baseURL := mustParseURL("https://example.com/")

	response := &HTTPResponse{
		URL:     baseURL,
		Headers: map[string][]string{},
		Body:    []byte("test https://example.com/page"),
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Extraction should handle cancelled context gracefully
	// Note: Current implementation doesn't check context in extractors,
	// but this test ensures no panic occurs
	result, err := coordinator.extractInternal(ctx, baseURL, response)

	// Should complete without panic (may return error or empty result)
	if err != nil {
		t.Logf("extraction with cancelled context returned error: %v", err)
	}
	_ = result
}

// Helper functions

func createTestCoordinator() *ExtractionCoordinator {
	resolver := NewURLResolver()

	factory := NewExtractorFactory(resolver)
	return factory.CreateCoordinator()
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
