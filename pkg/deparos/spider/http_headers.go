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
//
// Burp mapping:
//   - dkx.java (Location, Content-Location, Content-Base)
//   - f7e.java + fmw.java (Link header)
//   - dg6.java (Refresh header)
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
//
// Burp mapping: dkx.a(hik var1, hkk var2, byte[] var3, fi3 var4) - Lines 15-50
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
//
// Burp mapping: dkx.a() lines 23-49
func (e *HTTPHeaderExtractor) extractFromHeader(baseURL *url.URL, headerName, headerValue string, callback LinkCallback) {
	headerLower := strings.ToLower(headerName)

	var urlStr string
	var headerType string

	// Burp mapping: Lines 29-35
	switch headerLower {
	case "location":
		// Burp: var12.startsWith("location:")
		urlStr = strings.TrimSpace(headerValue)
		headerType = "Location"
	case "content-location":
		// Burp: var12.startsWith("content-location:")
		urlStr = strings.TrimSpace(headerValue)
		headerType = "Content-Location"
	case "content-base":
		// Burp: var12.startsWith("content-base:")
		urlStr = strings.TrimSpace(headerValue)
		headerType = "Content-Base"
	case "link":
		// Burp mapping: f7e.java lines 18-96 (Link header with rel=canonical)
		// Format: <url>; rel=canonical or <url1>, <url2>; rel=canonical
		urlStr = e.parseLinkHeader(headerValue)
		if urlStr == "" {
			return
		}
		headerType = "Link"
	case "refresh":
		// Burp mapping: dg6.java lines 207-303 (Refresh header)
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
	// Burp mapping: Line 38: at.a(var14, var1, this.a)
	resolved, err := e.urlResolver.Resolve(baseURL, urlStr)
	if err != nil {
		return
	}

	// Report discovered link
	// Burp mapping: Line 42: new v2((byte)1, var13, at.a(var14), null, null, (short)256, ...)
	link := &DiscoveredLink{
		SourceType:   SourceHTTPHeader,
		URL:          resolved,
		RawURL:       urlStr,
		ResourceType: ResourceHTML, // Burp uses (short)256 = HTML
		StartPos:     0,            // Header position not tracked in Burp
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
// Burp mapping: f7e.java lines 18-96
func (e *HTTPHeaderExtractor) parseLinkHeader(value string) string {
	if value == "" {
		return ""
	}

	// Split by comma for multiple links
	// Burp mapping: f7e.java line 20
	links := strings.Split(value, ",")

	for _, link := range links {
		// Split by semicolon to separate URL from parameters
		// Burp mapping: f7e.java line 23
		parts := strings.Split(link, ";")
		if len(parts) < 2 {
			continue
		}

		// Extract URL from <...>
		// Burp mapping: f7e.java lines 52-54
		urlPart := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(urlPart, "<") || !strings.HasSuffix(urlPart, ">") {
			continue
		}
		extractedURL := urlPart[1 : len(urlPart)-1]

		// Check for rel=canonical parameter
		// Burp mapping: f7e.java lines 26-34
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
// Burp mapping: f7e.java lines 57-77
func (e *HTTPHeaderExtractor) isCanonicalRel(param string) bool {
	// Check if parameter starts with rel=
	// Burp mapping: f7e.java line 60
	lowerParam := strings.ToLower(param)
	if !strings.HasPrefix(lowerParam, "rel=") {
		return false
	}

	// Extract value after rel=
	value := strings.TrimSpace(param[4:])

	// Handle quoted values: rel="canonical other"
	// Burp mapping: f7e.java lines 65-68
	if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		value = value[1 : len(value)-1]
	}

	// Check if "canonical" is in space-separated list
	// Burp mapping: f7e.java line 71
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
// Burp mapping: dg6.java lines 207-319
func (e *HTTPHeaderExtractor) parseRefreshHeader(value string) string {
	if value == "" {
		return ""
	}

	// Find url= (case-insensitive)
	// Burp mapping: dg6.java line 285
	lowerValue := strings.ToLower(value)
	idx := strings.Index(lowerValue, "url=")
	if idx == -1 {
		return ""
	}

	// Check minimum length
	// Burp mapping: dg6.java line 286
	if len(value) <= idx+4 {
		return ""
	}

	// Extract URL part after "url="
	// Burp mapping: dg6.java lines 287-288
	urlStart := idx + 4
	urlEnd := len(value)

	// Handle quoted URLs: url='...'
	// Burp mapping: dg6.java lines 291-297
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
