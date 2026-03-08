package spider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func TestCommentsExtractor(t *testing.T) {
	resolver := NewURLResolver()
	inlineScanner := NewInlineURLScanner(resolver)
	extractor := NewCommentsExtractor(inlineScanner)

	baseURL, _ := url.Parse("https://example.com/page.html")

	tests := []struct {
		name       string
		html       string
		wantURLs   []string
		wantSource LinkSourceType
	}{
		{
			name: "simple comment with http url",
			html: `<html><!-- https://hidden.example.com/admin --></html>`,
			wantURLs: []string{
				"https://hidden.example.com/admin",
			},
			wantSource: SourceInlineURL,
		},
		{
			name: "comment with multiple urls",
			html: `<html><!-- https://first.example.com and https://second.example.com --></html>`,
			wantURLs: []string{
				"https://first.example.com/",
				"https://second.example.com/",
			},
			wantSource: SourceInlineURL,
		},
		{
			name:       "comment with relative path",
			html:       `<html><!-- /admin/secret --></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name: "multiple comments in document",
			html: `<html>
				<!-- https://comment1.example.com -->
				<body>
				<!-- https://comment2.example.com -->
				</body>
			</html>`,
			wantURLs: []string{
				"https://comment1.example.com/",
				"https://comment2.example.com/",
			},
			wantSource: SourceInlineURL,
		},
		{
			name:       "comment without urls",
			html:       `<html><!-- This is just a comment --></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name:       "empty comment",
			html:       `<html><!----></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name: "comment with ws protocol",
			html: `<html><!-- ws://websocket.example.com:8080 --></html>`,
			wantURLs: []string{
				"ws://websocket.example.com:8080/",
			},
			wantSource: SourceInlineURL,
		},
		{
			name:       "nested comments (HTML allows only outer)",
			html:       `<html><!-- outer <!-- inner --> outer --></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name:       "comment with path variants",
			html:       `<html><!-- /api/v1/users /api/v2/users --></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name: "comment with special characters - query preserved",
			html: `<html><!-- https://example.com/search?q=test&lang=en --></html>`,
			wantURLs: []string{
				"https://example.com/search?q=test&lang=en",
			},
			wantSource: SourceInlineURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse HTML
			doc, err := html.Parse(strings.NewReader(tt.html))
			require.NoError(t, err)

			// Create response with parsed HTML
			response := &HTTPResponse{
				URL:  baseURL,
				Body: []byte(tt.html),
				HTML: doc,
			}

			// Extract links
			var links []*DiscoveredLink
			err = extractor.Extract(context.Background(), baseURL, response, func(link *DiscoveredLink) {
				links = append(links, link)
			})
			require.NoError(t, err)

			// Verify results
			assert.Equal(t, len(tt.wantURLs), len(links), "number of extracted links")

			for i, wantURL := range tt.wantURLs {
				require.True(t, i < len(links), "expected more links")
				assert.Equal(t, wantURL, links[i].URL.String())
				assert.Equal(t, tt.wantSource, links[i].SourceType)
			}
		})
	}
}

func TestCommentsExtractor_NoHTML(t *testing.T) {
	resolver := NewURLResolver()
	inlineScanner := NewInlineURLScanner(resolver)
	extractor := NewCommentsExtractor(inlineScanner)

	baseURL, _ := url.Parse("https://example.com/")
	response := &HTTPResponse{
		URL:  baseURL,
		HTML: nil,
	}

	var links []*DiscoveredLink
	err := extractor.Extract(context.Background(), baseURL, response, func(link *DiscoveredLink) {
		links = append(links, link)
	})

	require.NoError(t, err)
	assert.Empty(t, links)
}

// TestCommentsExtractor_InvalidHTMLType was removed because HTTPResponse.HTML
// is now strongly typed as *html.Node instead of interface{}. Invalid type
// assignment is now a compile-time error rather than a runtime check.

func TestCommentsExtractor_ImplementsInterface(t *testing.T) {
	resolver := NewURLResolver()
	inlineScanner := NewInlineURLScanner(resolver)
	extractor := NewCommentsExtractor(inlineScanner)

	// Verify it implements LinkExtractor
	var _ LinkExtractor = extractor
}
