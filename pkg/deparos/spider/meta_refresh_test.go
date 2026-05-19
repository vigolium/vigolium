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

func TestMetaRefreshExtractor(t *testing.T) {
	// Create resolver and scope checker
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	extractor := NewMetaRefreshExtractor(inlineScanner)

	baseURL, _ := url.Parse("https://example.com/page.html")

	tests := []struct {
		name       string
		html       string
		wantURLs   []string
		wantSource LinkSourceType
	}{
		{
			name: "meta refresh with url parameter",
			html: `<html><head><meta http-equiv="refresh" content="5;url=https://redirect.example.com/target"></head></html>`,
			wantURLs: []string{
				"https://redirect.example.com/target",
			},
			wantSource: SourceInlineURL,
		},
		{
			name: "meta refresh without delay",
			html: `<html><head><meta http-equiv="refresh" content="url=https://example.com/page"></head></html>`,
			wantURLs: []string{
				"https://example.com/page",
			},
			wantSource: SourceInlineURL,
		},
		{
			name: "meta refresh case insensitive http-equiv",
			html: `<html><head><meta HTTP-EQUIV="REFRESH" content="0;url=https://example.com/new"></head></html>`,
			wantURLs: []string{
				"https://example.com/new",
			},
			wantSource: SourceInlineURL,
		},
		{
			name:       "meta refresh with relative url",
			html:       `<html><head><meta http-equiv="refresh" content="url=/relative/path"></head></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name:       "meta refresh without url parameter",
			html:       `<html><head><meta http-equiv="refresh" content="5"></head></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name:       "meta without http-equiv",
			html:       `<html><head><meta name="description" content="https://example.com"></head></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name:       "empty content attribute",
			html:       `<html><head><meta http-equiv="refresh" content=""></head></html>`,
			wantURLs:   []string{},
			wantSource: SourceInlineURL,
		},
		{
			name: "meta refresh with ws protocol",
			html: `<html><head><meta http-equiv="refresh" content="url=ws://example.com:8080/ws"></head></html>`,
			wantURLs: []string{
				"ws://example.com:8080/ws",
			},
			wantSource: SourceInlineURL,
		},
		{
			name: "multiple meta tags",
			html: `<html><head>
				<meta http-equiv="refresh" content="url=https://first.example.com">
				<meta http-equiv="refresh" content="url=https://second.example.com">
			</head></html>`,
			wantURLs: []string{
				"https://first.example.com/",
				"https://second.example.com/",
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

func TestMetaRefreshExtractor_NoHTML(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	extractor := NewMetaRefreshExtractor(inlineScanner)

	baseURL, _ := url.Parse("https://example.com/")
	response := &HTTPResponse{
		URL:  baseURL,
		HTML: nil, // No parsed HTML
	}

	var links []*DiscoveredLink
	err := extractor.Extract(context.Background(), baseURL, response, func(link *DiscoveredLink) {
		links = append(links, link)
	})

	require.NoError(t, err)
	assert.Empty(t, links)
}

// TestMetaRefreshExtractor_InvalidHTMLType was removed because HTTPResponse.HTML
// is now strongly typed as *html.Node instead of interface{}. Invalid type
// assignment is now a compile-time error rather than a runtime check.

func TestMetaRefreshExtractor_ImplementsInterface(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	extractor := NewMetaRefreshExtractor(inlineScanner)

	// Verify it implements LinkExtractor
	var _ LinkExtractor = extractor
}
