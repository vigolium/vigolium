package spider

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPHeaderExtractor_Extract(t *testing.T) {
	resolver := NewURLResolver()

	extractor := NewHTTPHeaderExtractor(resolver)

	tests := []struct {
		name         string
		baseURL      string
		headers      map[string][]string
		expectedURLs map[string]struct {
			sourceType   LinkSourceType
			resourceType ResourceType
		}
	}{
		{
			name:    "Location header - absolute URL",
			baseURL: "https://example.com/page1",
			headers: map[string][]string{
				"Location": {"https://example.com/page2"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/page2": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Location header - relative URL",
			baseURL: "https://example.com/api/v1",
			headers: map[string][]string{
				"Location": {"/api/v2"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/api/v2": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Content-Location header",
			baseURL: "https://example.com/resource",
			headers: map[string][]string{
				"Content-Location": {"https://example.com/resource-alt"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/resource-alt": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Content-Base header (deprecated)",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Content-Base": {"https://example.com/base/"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/base/": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Multiple redirect headers",
			baseURL: "https://example.com/page1",
			headers: map[string][]string{
				"Location":         {"https://example.com/page2"},
				"Content-Location": {"https://example.com/page3"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/page2": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
				"https://example.com/page3": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Case insensitive header names",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"LOCATION":         {"https://example.com/page1"},
				"Content-Location": {"https://example.com/page2"},
				"content-base":     {"https://example.com/page3"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/page1": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
				"https://example.com/page2": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
				"https://example.com/page3": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Whitespace trimming",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Location": {"  https://example.com/page2  "},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/page2": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Irrelevant headers ignored",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Content-Type":   {"text/html"},
				"Content-Length": {"1234"},
				"Set-Cookie":     {"session=abc123"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{},
		},
		{
			name:    "Empty header value",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Location": {""},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{},
		},
		{
			name:    "Out of scope URL returned (scope check happens at engine level)",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Location": {"https://other.com/page"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://other.com/page": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Subdomain in scope",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Location": {"https://api.example.com/resource"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://api.example.com/resource": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Link header with rel=canonical",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Link": {"<https://example.com/canonical>; rel=canonical"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/canonical": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Link header with quoted rel",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Link": {`<https://example.com/canonical>; rel="canonical"`},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/canonical": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Link header with multiple rels",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Link": {`<https://example.com/canonical>; rel="canonical alternate"`},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/canonical": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Link header comma-separated",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Link": {"</other>; rel=alternate, <https://example.com/canonical>; rel=canonical"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/canonical": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Link header relative URL",
			baseURL: "https://example.com/dir/page",
			headers: map[string][]string{
				"Link": {"</canonical>; rel=canonical"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/canonical": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Link header without rel=canonical ignored",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Link": {"<https://example.com/alternate>; rel=alternate"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{},
		},
		{
			name:    "Refresh header with delay",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Refresh": {"5; url=https://example.com/redirect"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/redirect": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Refresh header no delay",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Refresh": {"0; url=https://example.com/redirect"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/redirect": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Refresh header with quoted URL",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Refresh": {"5; url='https://example.com/redirect'"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/redirect": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Refresh header relative URL",
			baseURL: "https://example.com/dir/page",
			headers: map[string][]string{
				"Refresh": {"0; url=/redirect"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/redirect": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Refresh header case-insensitive url=",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Refresh": {"0; URL=https://example.com/redirect"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/redirect": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
		{
			name:    "Multiple different headers",
			baseURL: "https://example.com/page",
			headers: map[string][]string{
				"Location": {"https://example.com/loc"},
				"Link":     {"<https://example.com/canonical>; rel=canonical"},
				"Refresh":  {"0; url=https://example.com/refresh"},
			},
			expectedURLs: map[string]struct {
				sourceType   LinkSourceType
				resourceType ResourceType
			}{
				"https://example.com/loc": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
				"https://example.com/canonical": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
				"https://example.com/refresh": {
					sourceType:   SourceHTTPHeader,
					resourceType: ResourceHTML,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, err := url.Parse(tt.baseURL)
			require.NoError(t, err)

			response := &HTTPResponse{
				URL:     baseURL,
				Headers: tt.headers,
			}

			discovered := []*DiscoveredLink{}
			callback := func(link *DiscoveredLink) {
				discovered = append(discovered, link)
			}

			err = extractor.Extract(context.Background(), baseURL, response, callback)
			require.NoError(t, err)

			// Validate exact count
			require.Len(t, discovered, len(tt.expectedURLs), "Unexpected number of discovered links")

			// Build discovered set for comparison
			discoveredSet := make(map[string]*DiscoveredLink)
			for _, link := range discovered {
				discoveredSet[link.URL.String()] = link
			}

			// Validate every expected URL is present with exact attributes
			for expectedURL, expectedAttrs := range tt.expectedURLs {
				link, found := discoveredSet[expectedURL]
				require.True(t, found, "Expected URL not found: %s", expectedURL)
				require.Equal(t, expectedAttrs.sourceType, link.SourceType, "Wrong SourceType for %s", expectedURL)
				require.Equal(t, expectedAttrs.resourceType, link.ResourceType, "Wrong ResourceType for %s", expectedURL)
			}

			// Validate no unexpected URLs
			for discoveredURL := range discoveredSet {
				_, expected := tt.expectedURLs[discoveredURL]
				require.True(t, expected, "Unexpected URL discovered: %s", discoveredURL)
			}
		})
	}
}

func TestHTTPHeaderExtractor_NilHeaders(t *testing.T) {
	resolver := NewURLResolver()
	extractor := NewHTTPHeaderExtractor(resolver)

	baseURL, _ := url.Parse("https://example.com")
	response := &HTTPResponse{
		URL:     baseURL,
		Headers: nil, // Nil headers
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := extractor.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)
	require.Len(t, discovered, 0)
}

func TestHTTPHeaderExtractor_InvalidURL(t *testing.T) {
	resolver := NewURLResolver()
	extractor := NewHTTPHeaderExtractor(resolver)

	baseURL, _ := url.Parse("https://example.com")
	response := &HTTPResponse{
		URL: baseURL,
		Headers: map[string][]string{
			"Location": {"://invalid-url"},
		},
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := extractor.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err) // Should not error, just skip invalid URLs
	require.Len(t, discovered, 0)
}

func BenchmarkHTTPHeaderExtractor_Extract(b *testing.B) {
	resolver := NewURLResolver()

	extractor := NewHTTPHeaderExtractor(resolver)

	baseURL, _ := url.Parse("https://example.com/page")
	response := &HTTPResponse{
		URL: baseURL,
		Headers: map[string][]string{
			"Location":         {"https://example.com/redirect"},
			"Content-Location": {"https://example.com/alt"},
			"Content-Type":     {"text/html"},
			"Content-Length":   {"1234"},
		},
	}

	callback := func(link *DiscoveredLink) {
		// No-op
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(context.Background(), baseURL, response, callback)
	}
}
