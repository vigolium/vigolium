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

func TestEventHandlersExtractor(t *testing.T) {
	resolver := NewURLResolver()
	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewEventHandlersExtractor(inlineScanner, jsExtractor)

	baseURL, _ := url.Parse("https://example.com/page.html")

	tests := []struct {
		name          string
		html          string
		expectedLinks []expectedLink
	}{
		{
			name: "onclick with javascript protocol",
			html: `<html><body><button onclick="javascript:window.location='https://redirect.example.com'">Click</button></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://redirect.example.com/",
					rawURL:       "https://redirect.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown, // No extension
				},
			},
		},
		{
			name: "onload with javascript protocol",
			html: `<html><body onload="javascript:fetch('https://api.example.com/init')"></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://api.example.com/init",
					rawURL:       "https://api.example.com/init",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "onmouseover with javascript",
			html: `<html><body><div onmouseover="javascript:window.location.href='https://tracker.example.com'">Hover</div></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://tracker.example.com/",
					rawURL:       "https://tracker.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "onclick with direct javascript code",
			html: `<html><body><button onclick="var x = 'https://example.com/api'">Click</button></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/api",
					rawURL:       "https://example.com/api",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "multiple event handlers on same element",
			html: `<html><body><div onclick="javascript:window.open('https://first.example.com')" onmouseover="javascript:fetch('https://second.example.com')">Element</div></body></html>`,
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
			name: "multiple elements with event handlers",
			html: `<html><body>
				<button onclick="javascript:location='https://btn1.example.com'">Button 1</button>
				<a href="javascript:void(0)" onclick="javascript:location='https://btn2.example.com'">Link</a>
			</body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://btn1.example.com/",
					rawURL:       "https://btn1.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
				{
					url:          "https://btn2.example.com/",
					rawURL:       "https://btn2.example.com",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name:          "relative path in javascript",
			html:          `<html><body><button onclick="javascript:window.location='/admin'">Click</button></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name:          "event handler without javascript",
			html:          `<html><body><button onclick="doSomething()">Click</button></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name: "onerror attribute",
			html: `<html><body><img src="notfound.jpg" onerror="javascript:fetch('https://api.example.com/log')"></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://api.example.com/log",
					rawURL:       "https://api.example.com/log",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
			},
		},
		{
			name: "javascript protocol with ws",
			html: `<html><body><button onclick="javascript:var ws = 'ws://websocket.example.com:8080'">WebSocket</button></body></html>`,
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
			name: "inline attribute with absolute url",
			html: `<html><body><a href="https://example.com/page" onclick="var x = 'https://tracker.example.com'">Link</a></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/page",
					rawURL:       "https://example.com/page",
					sourceType:   SourceInlineURL,
					resourceType: ResourceUnknown,
				},
				{
					url:          "https://tracker.example.com/",
					rawURL:       "https://tracker.example.com",
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

			// Validate exact link count
			require.Len(t, links, len(tt.expectedLinks), "Expected %d links, got %d", len(tt.expectedLinks), len(links))

			// Validate all link fields
			for i, expected := range tt.expectedLinks {
				actual := links[i]
				assert.Equal(t, expected.url, actual.URL.String(), "Link %d URL mismatch", i)
				assert.Equal(t, expected.rawURL, actual.RawURL, "Link %d RawURL mismatch", i)
				assert.Equal(t, expected.sourceType, actual.SourceType, "Link %d SourceType mismatch", i)
				assert.Equal(t, expected.resourceType, actual.ResourceType, "Link %d ResourceType mismatch", i)

				// Element and Attribute are only set for HTMLAttribute source type
				if expected.sourceType == SourceHTMLAttribute {
					assert.Equal(t, expected.element, actual.Element, "Link %d Element mismatch", i)
					assert.Equal(t, expected.attribute, actual.Attribute, "Link %d Attribute mismatch", i)
				}
			}
		})
	}
}

func TestEventHandlersExtractor_SkipsASPNETAttributes(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewEventHandlersExtractor(inlineScanner, jsExtractor)

	baseURL, _ := url.Parse("https://example.com/page.html")

	tests := []struct {
		name          string
		html          string
		expectedLinks []expectedLink
	}{
		{
			name:          "skip __VIEWSTATE",
			html:          `<html><body><input type="hidden" name="__VIEWSTATE" value="https://example.com"></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name:          "skip __EVENTVALIDATION",
			html:          `<html><body><input type="hidden" name="__EVENTVALIDATION" value="https://example.com"></body></html>`,
			expectedLinks: []expectedLink{},
		},
		{
			name: "process normal inputs",
			html: `<html><body><input type="hidden" name="token" value="https://example.com"></body></html>`,
			expectedLinks: []expectedLink{
				{
					url:          "https://example.com/",
					rawURL:       "https://example.com",
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

			// Validate exact link count
			require.Len(t, links, len(tt.expectedLinks), "Expected %d links, got %d", len(tt.expectedLinks), len(links))

			// Validate all link fields
			for i, expected := range tt.expectedLinks {
				actual := links[i]
				assert.Equal(t, expected.url, actual.URL.String(), "Link %d URL mismatch", i)
				assert.Equal(t, expected.rawURL, actual.RawURL, "Link %d RawURL mismatch", i)
				assert.Equal(t, expected.sourceType, actual.SourceType, "Link %d SourceType mismatch", i)
				assert.Equal(t, expected.resourceType, actual.ResourceType, "Link %d ResourceType mismatch", i)

				// Element and Attribute are only set for HTMLAttribute source type
				if expected.sourceType == SourceHTMLAttribute {
					assert.Equal(t, expected.element, actual.Element, "Link %d Element mismatch", i)
					assert.Equal(t, expected.attribute, actual.Attribute, "Link %d Attribute mismatch", i)
				}
			}
		})
	}
}

func TestEventHandlersExtractor_NoHTML(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewEventHandlersExtractor(inlineScanner, jsExtractor)

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

// TestEventHandlersExtractor_InvalidHTMLType was removed because HTTPResponse.HTML
// is now strongly typed as *html.Node instead of interface{}. Invalid type
// assignment is now a compile-time error rather than a runtime check.

func TestEventHandlersExtractor_ImplementsInterface(t *testing.T) {
	resolver := NewURLResolver()

	inlineScanner := NewInlineURLScanner(resolver)
	htmlExtractor := NewHTMLAttributeExtractor(resolver)
	jsExtractor := NewJavaScriptStringExtractor(inlineScanner, htmlExtractor)
	extractor := NewEventHandlersExtractor(inlineScanner, jsExtractor)

	// Verify it implements LinkExtractor
	var _ LinkExtractor = extractor
}
