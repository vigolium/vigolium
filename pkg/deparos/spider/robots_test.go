package spider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRobotsTxtParser_Extract_BasicDisallow(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow: /admin
Disallow: /private
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 4)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/private",
			},
			RawURL:       "/private",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/private/",
			},
			RawURL:       "/private/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_Allow(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Allow: /public
Allow: /api
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 4)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public",
			},
			RawURL:       "/public",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public/",
			},
			RawURL:       "/public/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api",
			},
			RawURL:       "/api",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/",
			},
			RawURL:       "/api/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_Sitemap(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 2)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap.xml",
			},
			RawURL:       "https://example.com/sitemap.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap2.xml",
			},
			RawURL:       "https://example.com/sitemap2.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_Comments(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`# This is a comment
Disallow: /admin # This is an inline comment
# Another comment
Allow: /public
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 4)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public",
			},
			RawURL:       "/public",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public/",
			},
			RawURL:       "/public/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_Mixed(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`# Standard robots.txt
Allow: /public
Disallow: /admin
Disallow: /private
Sitemap: https://example.com/sitemap.xml
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 7)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public",
			},
			RawURL:       "/public",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public/",
			},
			RawURL:       "/public/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/private",
			},
			RawURL:       "/private",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/private/",
			},
			RawURL:       "/private/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap.xml",
			},
			RawURL:       "https://example.com/sitemap.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_PathsWithTrailingSlash(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow: /admin/
Allow: /api/
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 2)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/",
			},
			RawURL:       "/api/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_NotRobotsTxtURL(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/sitemap.xml")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow: /admin
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 0)
}

func TestRobotsTxtParser_Extract_RobotsTxtCaseSensitive(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	tests := []struct {
		name          string
		urlPath       string
		shouldProcess bool
		expectedCount int
	}{
		{"/robots.txt", "/robots.txt", true, 2},
		{"/Robots.txt", "/Robots.txt", true, 2},
		{"/ROBOTS.TXT", "/ROBOTS.TXT", true, 2},
		{"/robots.txt/", "/robots.txt/", false, 0},
		{"/api/robots.txt", "/api/robots.txt", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, _ := url.Parse("https://example.com" + tt.urlPath)
			response := &HTTPResponse{
				URL: baseURL,
				Body: []byte(`Disallow: /admin
`),
			}

			discovered := []*DiscoveredLink{}
			callback := func(link *DiscoveredLink) {
				discovered = append(discovered, link)
			}

			_ = parser.Extract(context.Background(), baseURL, response, callback)

			require.Len(t, discovered, tt.expectedCount)

			if tt.shouldProcess {
				expectedLinks := []*DiscoveredLink{
					{
						URL: &url.URL{
							Scheme: "https",
							Host:   "example.com",
							Path:   "/admin",
						},
						RawURL:       "/admin",
						SourceType:   SourceRobotsTxt,
						ResourceType: ResourceHTML,
						StartPos:     -1,
						EndPos:       -1,
						Element:      "robots.txt",
						Attribute:    "",
					},
					{
						URL: &url.URL{
							Scheme: "https",
							Host:   "example.com",
							Path:   "/admin/",
						},
						RawURL:       "/admin/",
						SourceType:   SourceRobotsTxt,
						ResourceType: ResourceHTML,
						StartPos:     -1,
						EndPos:       -1,
						Element:      "robots.txt",
						Attribute:    "",
					},
				}
				assert.ElementsMatch(t, expectedLinks, discovered)
			}
		})
	}
}

func TestRobotsTxtParser_Extract_EmptyBody(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL:  baseURL,
		Body: []byte{},
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)
	require.Len(t, discovered, 0)
}

func TestRobotsTxtParser_Extract_EmptyLines(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`
Disallow: /admin

Allow: /public

`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 4)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public",
			},
			RawURL:       "/public",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public/",
			},
			RawURL:       "/public/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_CaseInsensitiveDirectives(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`DISALLOW: /admin
allow: /public
SiTeMap: https://example.com/sitemap.xml
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 5)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public",
			},
			RawURL:       "/public",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public/",
			},
			RawURL:       "/public/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap.xml",
			},
			RawURL:       "https://example.com/sitemap.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_WhitespaceHandling(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow:    /admin
  Allow:  /public
  Sitemap:   https://example.com/sitemap.xml
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 5)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public",
			},
			RawURL:       "/public",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/public/",
			},
			RawURL:       "/public/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap.xml",
			},
			RawURL:       "https://example.com/sitemap.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_Wildcard_Rejection(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow: /admin*
Disallow: /*admin
Disallow: /admin
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 2)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)

	for _, link := range discovered {
		assert.False(t, strings.Contains(link.URL.String(), "*"))
	}
}

func TestRobotsTxtParser_Extract_OutOfScope(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow: /admin
Sitemap: https://other.com/sitemap.xml
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	// Now returns 3 links (scope check happens at engine level, not extractor)
	require.Len(t, discovered, 3)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "other.com",
				Path:   "/sitemap.xml",
			},
			RawURL:       "https://other.com/sitemap.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func TestRobotsTxtParser_Extract_RelativeSitemapURL(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Sitemap: /sitemap.xml
Sitemap: ./sitemap2.xml
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 2)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap.xml",
			},
			RawURL:       "/sitemap.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/sitemap2.xml",
			},
			RawURL:       "./sitemap2.xml",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceBinary,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)

	for _, link := range discovered {
		assert.Equal(t, "https", link.URL.Scheme)
		assert.Equal(t, "example.com", link.URL.Host)
		assert.True(t, strings.HasSuffix(link.URL.Path, ".xml"))
	}
}

func TestRobotsTxtParser_Extract_NilURL(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	response := &HTTPResponse{
		URL:  nil,
		Body: []byte(`Disallow: /admin`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), nil, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 0)
}

func TestRobotsTxtParser_Extract_NilScopeChecker(t *testing.T) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`Disallow: /admin
`),
	}

	discovered := []*DiscoveredLink{}
	callback := func(link *DiscoveredLink) {
		discovered = append(discovered, link)
	}

	err := parser.Extract(context.Background(), baseURL, response, callback)
	require.NoError(t, err)

	require.Len(t, discovered, 2)

	expectedLinks := []*DiscoveredLink{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin",
			},
			RawURL:       "/admin",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/admin/",
			},
			RawURL:       "/admin/",
			SourceType:   SourceRobotsTxt,
			ResourceType: ResourceHTML,
			StartPos:     -1,
			EndPos:       -1,
			Element:      "robots.txt",
			Attribute:    "",
		},
	}

	assert.ElementsMatch(t, expectedLinks, discovered)
}

func BenchmarkRobotsTxtParser_Extract(b *testing.B) {
	resolver := NewURLResolver()

	parser := NewRobotsTxtParser(resolver)

	baseURL, _ := url.Parse("https://example.com/robots.txt")
	response := &HTTPResponse{
		URL: baseURL,
		Body: []byte(`# Standard robots.txt
User-agent: *
Allow: /public
Disallow: /admin
Disallow: /private
Disallow: /api/internal
Disallow: /secret
Disallow: /secure
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap-products.xml
Sitemap: https://example.com/sitemap-news.xml
`),
	}

	callback := func(link *DiscoveredLink) {
		// No-op
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Extract(context.Background(), baseURL, response, callback)
	}
}
