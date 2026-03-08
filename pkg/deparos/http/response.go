package http

import (
	nethttp "net/http"
	"strings"
)

// ContentTypeInfo represents parsed Content-Type information.
type ContentTypeInfo struct {
	// MediaType is the main content type (e.g., "text/html")
	MediaType string

	// Charset is the character encoding (e.g., "utf-8")
	Charset string

	// IsText indicates if the content is text-based
	IsText bool

	// IsHTML indicates if the content is HTML
	IsHTML bool

	// IsJSON indicates if the content is JSON
	IsJSON bool

	// IsXML indicates if the content is XML
	IsXML bool
}

// ParseContentType parses the Content-Type header and returns structured information.
func ParseContentType(contentType string) *ContentTypeInfo {
	info := &ContentTypeInfo{}

	if contentType == "" {
		return info
	}

	// Split by semicolon to separate media type from parameters
	parts := strings.Split(contentType, ";")
	if len(parts) > 0 {
		info.MediaType = strings.TrimSpace(strings.ToLower(parts[0]))
	}

	// Parse charset parameter
	for i := 1; i < len(parts); i++ {
		param := strings.TrimSpace(parts[i])
		if strings.HasPrefix(param, "charset=") {
			info.Charset = strings.TrimSpace(param[8:])
		}
	}

	// Classify content type
	info.IsHTML = strings.HasPrefix(info.MediaType, "text/html") ||
		strings.HasPrefix(info.MediaType, "application/xhtml")

	info.IsJSON = strings.Contains(info.MediaType, "json")

	info.IsXML = strings.Contains(info.MediaType, "xml")

	info.IsText = strings.HasPrefix(info.MediaType, "text/") ||
		info.IsJSON || info.IsXML

	return info
}

// IsSuccessStatus returns true for HTTP success status codes (2xx).
func IsSuccessStatus(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// IsRedirectStatus returns true for HTTP redirect status codes (3xx).
func IsRedirectStatus(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

// IsClientErrorStatus returns true for HTTP client error status codes (4xx).
func IsClientErrorStatus(statusCode int) bool {
	return statusCode >= 400 && statusCode < 500
}

// IsServerErrorStatus returns true for HTTP server error status codes (5xx).
func IsServerErrorStatus(statusCode int) bool {
	return statusCode >= 500 && statusCode < 600
}

// IsNotFound returns true for 404 Not Found status.
func IsNotFound(statusCode int) bool {
	return statusCode == nethttp.StatusNotFound
}

// IsUnauthorized returns true for 401 Unauthorized or 403 Forbidden.
func IsUnauthorized(statusCode int) bool {
	return statusCode == nethttp.StatusUnauthorized || statusCode == nethttp.StatusForbidden
}

// IsChunkedEncoding checks if the response uses chunked transfer encoding.
func IsChunkedEncoding(headers nethttp.Header) bool {
	te := headers.Get("Transfer-Encoding")
	return strings.Contains(strings.ToLower(te), "chunked")
}

// GetContentLength returns the Content-Length header value, or -1 if not present.
func GetContentLength(headers nethttp.Header) int64 {
	cl := headers.Get("Content-Length")
	if cl == "" {
		return -1
	}

	// Parse Content-Length value
	var length int64
	for _, c := range cl {
		if c < '0' || c > '9' {
			return -1 // Invalid format
		}
		length = length*10 + int64(c-'0')
	}

	return length
}

// ResponseMetadata contains extracted metadata from an HTTP response.
type ResponseMetadata struct {
	StatusCode    int
	ContentType   *ContentTypeInfo
	ContentLength int64
	IsChunked     bool
	Headers       map[string]string
	Body          []byte
	OriginalURL   string
	FinalURL      string // After redirects
	RedirectCount int
}

// ExtractMetadata extracts metadata from an HTTP response.
func ExtractMetadata(resp *nethttp.Response, body []byte) *ResponseMetadata {
	metadata := &ResponseMetadata{
		StatusCode:    resp.StatusCode,
		ContentType:   ParseContentType(resp.Header.Get("Content-Type")),
		ContentLength: GetContentLength(resp.Header),
		IsChunked:     IsChunkedEncoding(resp.Header),
		Body:          body,
		Headers:       make(map[string]string),
	}

	// Extract key headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			metadata.Headers[key] = values[0]
		}
	}

	// URL tracking
	if resp.Request != nil {
		metadata.OriginalURL = resp.Request.URL.String()
		metadata.FinalURL = resp.Request.URL.String()
	}

	return metadata
}
