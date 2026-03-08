package spider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func TestScriptContentExtractor(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewScriptContentExtractor(inlineScanner, jsExtractor)

	baseURL, _ := url.Parse("https://example.com/page.html")

	tests := []struct {
		name          string
		html          string
		expectedLinks []expectedLink
	}{
		{
			name: "script with inline absolute url",
			html: `<html><body><script>var x = 'https://api.example.com/data';</script></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://api.example.com/data",
					rawURL:       "https://api.example.com/data",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name:          "script with relative path",
			html:          `<html><body><script>var url = '/api/users';</script></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name: "script with multiple urls",
			html: `<html><body><script>
				var api1 = 'https://api1.example.com';
				var api2 = 'https://api2.example.com';
			</script></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://api1.example.com/",
					rawURL:       "https://api1.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
				{
					url:          "https://api2.example.com/",
					rawURL:       "https://api2.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "script with fetch call",
			html: `<html><body><script>
				fetch('https://backend.example.com/api')
					.then(r => r.json());
			</script></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://backend.example.com/api",
					rawURL:       "https://backend.example.com/api",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "multiple script tags",
			html: `<html><body>
				<script>var x = 'https://first.example.com';</script>
				<script>var y = 'https://second.example.com';</script>
			</body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://first.example.com/",
					rawURL:       "https://first.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
				{
					url:          "https://second.example.com/",
					rawURL:       "https://second.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name:          "script with only comments",
			html:          `<html><body><script>// This is a comment</script></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name:          "empty script tag",
			html:          `<html><body><script></script></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name: "script with escaped quotes",
			html: `<html><body><script>var s = "https://example.com/path\\"with\\"quotes";</script></body></html>`,
			expectedLinks: []expectedLink{
				{
					// The JS string contains: path\"with\"quotes
					// Extractor stops at the embedded quote, extracting: path\\
					// Backslashes are sanitized during URL resolution
					url:          "https://example.com/path",
					rawURL:       "https://example.com/path\\\\",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "script with ws protocol",
			html: `<html><body><script>var ws = 'ws://websocket.example.com:8080';</script></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "ws://websocket.example.com:8080/",
					rawURL:       "ws://websocket.example.com:8080",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "script with query parameters",
			html: `<html><body><script>var url = 'https://example.com/search?q=test&limit=10';</script></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/search?q=test&limit=10",
					rawURL:       "https://example.com/search?q=test&limit=10",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
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

			// Validate exact count
			require.Len(t, links, len(tt.expectedLinks), "Expected %d links, got %d", len(tt.expectedLinks), len(links))

			// Validate each discovered link
			for i, expected := range tt.expectedLinks {
				actual := links[i]
				require.Equal(t, expected.url, actual.URL.String(), "Link %d URL mismatch", i)
				require.Equal(t, expected.rawURL, actual.RawURL, "Link %d RawURL mismatch", i)
				require.Equal(t, expected.sourceType, actual.SourceType, "Link %d SourceType mismatch", i)
				require.Equal(t, expected.resourceType, actual.ResourceType, "Link %d ResourceType mismatch", i)
			}
		})
	}
}

func TestScriptContentExtractor_NoHTML(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewScriptContentExtractor(inlineScanner, jsExtractor)

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
	require.Empty(t, links)
}

// TestScriptContentExtractor_InvalidHTMLType was removed because HTTPResponse.HTML
// is now strongly typed as *html.Node instead of interface{}. Invalid type
// assignment is now a compile-time error rather than a runtime check.

func TestScriptContentExtractor_ImplementsInterface(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewScriptContentExtractor(inlineScanner, jsExtractor)

	// Verify it implements LinkExtractor
	var _ LinkExtractor = extractor
}
