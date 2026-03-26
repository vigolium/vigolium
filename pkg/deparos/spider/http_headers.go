package spider

import (
	"context"
	"net/url"
	"strings"
)

// HTTPHeaderExtractor extracts URLs from HTTP response headers.
//
// Supported headers:
//   - Location: Redirect target
//   - Content-Location: Alternative location for the resource
//   - Content-Base: Base URL for relative URLs (deprecated but still used)
//   - Link: Canonical link relations (e.g., <url>; rel=canonical)
//   - Refresh: Meta refresh in HTTP header (e.g., 0; url=https://example.com/)
type HTTPHeaderExtractor struct {
	urlResolver *URLResolver
}

// NewHTTPHeaderExtractor creates a new HTTP header extractor.
func NewHTTPHeaderExtractor(urlResolver *URLResolver) *HTTPHeaderExtractor {
	return &HTTPHeaderExtractor{
		urlResolver: urlResolver,
	}
}

// Extract examines HTTP response headers and reports discovered URLs.
func (e *HTTPHeaderExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	if response.Headers == nil {
		return nil
	}

	// Check each header
	for headerName, headerValues := range response.Headers {
		for _, headerValue := range headerValues {
			e.extractFromHeader(baseURL, headerName, headerValue, callback)
		}
	}

	return nil
}

// extractFromHeader extracts URLs from a single header.
func (e *HTTPHeaderExtractor) extractFromHeader(baseURL *url.URL, headerName, headerValue string, callback LinkCallback) {
	headerLower := strings.ToLower(headerName)

	var urlStr string
	var headerType string

	switch headerLower {
	case "location":
		urlStr = strings.TrimSpace(headerValue)
		headerType = "Location"
	case "content-location":
		urlStr = strings.TrimSpace(headerValue)
		headerType = "Content-Location"
	case "content-base":
		urlStr = strings.TrimSpace(headerValue)
		headerType = "Content-Base"
	case "link":
		// Format: <url>; rel=canonical or <url1>, <url2>; rel=canonical
		urlStr = e.parseLinkHeader(headerValue)
		if urlStr == "" {
			return
		}
		headerType = "Link"
	case "refresh":
		// Format: 0; url=https://example.com/ or 5; url='https://example.com/'
		urlStr = e.parseRefreshHeader(headerValue)
		if urlStr == "" {
			return
		}
		headerType = "Refresh"
	default:
		return // Not a relevant header
	}

	if urlStr == "" {
		return
	}

	// Parse and resolve URL
	resolved, err := e.urlResolver.Resolve(baseURL, urlStr)
	if err != nil {
		return
	}

	// Report discovered link
	link := &DiscoveredLink{
		SourceType:   SourceHTTPHeader,
		URL:          resolved,
		RawURL:       urlStr,
		ResourceType: ResourceHTML,
		StartPos:     0,
		EndPos:       len(urlStr),
		Element:      headerType, // Store which header it came from
		Attribute:    headerName, // Store original header name
	}

	callback(link)
}

// parseLinkHeader extracts canonical URL from Link header.
//
// Supports formats:
//   - Link: <https://example.com/>; rel=canonical
//   - Link: <https://example.com/>; rel="canonical"
//   - Link: <https://example.com/>; rel="canonical alternate"
//   - Link: </path>, </other>; rel=canonical (comma-separated)
//
func (e *HTTPHeaderExtractor) parseLinkHeader(value string) string {
	if value == "" {
		return ""
	}

	// Split by comma for multiple links
	links := strings.Split(value, ",")

	for _, link := range links {
		// Split by semicolon to separate URL from parameters
		parts := strings.Split(link, ";")
		if len(parts) < 2 {
			continue
		}

		// Extract URL from <...>
		urlPart := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(urlPart, "<") || !strings.HasSuffix(urlPart, ">") {
			continue
		}
		extractedURL := urlPart[1 : len(urlPart)-1]

		// Check for rel=canonical parameter
		for i := 1; i < len(parts); i++ {
			param := strings.TrimSpace(parts[i])
			if e.isCanonicalRel(param) {
				return extractedURL
			}
		}
	}

	return ""
}

// isCanonicalRel checks if a parameter is rel=canonical.
//
// Supports:
//   - rel=canonical
//   - rel="canonical"
//   - rel="canonical alternate" (space-separated list)
//
func (e *HTTPHeaderExtractor) isCanonicalRel(param string) bool {
	// Check if parameter starts with rel=
	lowerParam := strings.ToLower(param)
	if !strings.HasPrefix(lowerParam, "rel=") {
		return false
	}

	// Extract value after rel=
	value := strings.TrimSpace(param[4:])

	// Handle quoted values: rel="canonical other"
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		value = value[1 : len(value)-1]
	}

	// Check if "canonical" is in space-separated list
	rels := strings.Fields(strings.ToLower(value))
	for _, rel := range rels {
		if rel == "canonical" {
			return true
		}
	}

	return false
}

// parseRefreshHeader extracts URL from Refresh header.
//
// Supports formats:
//   - Refresh: 0; url=https://example.com/
//   - Refresh: 5; url='https://example.com/'
//   - Refresh: url=https://example.com/ (no delay)
//
func (e *HTTPHeaderExtractor) parseRefreshHeader(value string) string {
	if value == "" {
		return ""
	}

	// Find url= (case-insensitive)
	lowerValue := strings.ToLower(value)
	idx := strings.Index(lowerValue, "url=")
	if idx == -1 {
		return ""
	}

	// Check minimum length
	if len(value) <= idx+4 {
		return ""
	}

	// Extract URL part after "url="
	urlStart := idx + 4
	urlEnd := len(value)

	// Handle quoted URLs: url='...'
	if urlEnd-urlStart > 2 && value[urlStart] == '\'' {
		urlStart++
		if value[urlEnd-1] == '\'' {
			urlEnd--
		}
	}

	return value[urlStart:urlEnd]
}

// Ensure HTTPHeaderExtractor implements LinkExtractor
var _ LinkExtractor = (*HTTPHeaderExtractor)(nil)
