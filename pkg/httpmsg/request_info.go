package httpmsg

// ContentType represents the content type of an HTTP request body.
// Values match Burp Suite's IRequestInfo CONTENT_TYPE_* constants.
type ContentType byte

const (
	// ContentTypeNone represents no body or cookie-only content (value: 0)
	ContentTypeNone ContentType = 0

	// ContentTypeURLEncoded represents application/x-www-form-urlencoded (value: 1)
	ContentTypeURLEncoded ContentType = 1

	// ContentTypeMultipart represents multipart/form-data (value: 2)
	ContentTypeMultipart ContentType = 2

	// ContentTypeXML represents XML content (value: 3)
	ContentTypeXML ContentType = 3

	// ContentTypeJSON represents application/json (value: 4)
	ContentTypeJSON ContentType = 4

	// ContentTypeAMF represents serialized AMF (Action Message Format) (value: 5)
	ContentTypeAMF ContentType = 5

	// ContentTypeUnknown represents unknown content type (value: 255)
	ContentTypeUnknown ContentType = 255
)

// RequestInfo represents parsed HTTP request information.
// Ported from Burp Suite's dz8.java class and IRequestInfo interface.
// This is the primary container for analyzed request data, matching Burp's internal structure.
//
// Field layout:
// - Headers: HTTP headers including request line
// - HTTPVersion: HTTP version (11 for HTTP/1.1)
// - BodyOffset: byte offset where body starts
// - Method: HTTP method (GET, POST, etc.)
// - URL: request path with query string
// - HasBody: whether request has a body
// - HttpService: Host header value
// - ContentType: parsed content type
// - Parameters: extracted parameters from URL, body, cookies
type RequestInfo struct {
	// Headers is the list of HTTP header strings (including the request line)
	// Maps to dz8.d and IRequestInfo.getHeaders()
	// Example: ["GET /path HTTP/1.1", "Host: example.com", "User-Agent: ..."]
	Headers []string

	// HTTPVersion indicates the HTTP version as an integer
	// Maps to dz8.e
	// Example: 11 for HTTP/1.1, 20 for HTTP/2.0
	HTTPVersion int

	// BodyOffset is the byte offset where the message body begins
	// Maps to dz8.h (via dz8.a() method) and IRequestInfo.getBodyOffset()
	// This is the position immediately after the \r\n\r\n (or \n\n) separator
	BodyOffset int

	// Method is the HTTP request method (GET, POST, etc.)
	// Maps to dz8.f and IRequestInfo.getMethod()
	Method string

	// URL is the full request URL as a string
	// Maps to dz8.g (converted from hik type) and IRequestInfo.getUrl()
	// Note: hik is Burp's internal URL representation; we use string here
	URL string

	// HasBody indicates whether the request contains a message body
	// Maps to dz8.b
	// True for POST/PUT/PATCH requests, false for GET/HEAD/etc.
	HasBody bool

	// HttpService stores the target host from the Host header
	// Extracted from the request headers during AnalyzeRequest
	// Example: "example.com" or "example.com:8080"
	HttpService string

	// ContentType indicates the request body content type
	// Maps to dz8.a (h5p enum)
	// Uses ContentType constants defined above
	ContentType ContentType

	// Parameters is the list of extracted HTTP parameters
	// Maps to dz8.c and IRequestInfo.getParameters()
	// Includes URL params, body params, cookies, etc. depending on request type
	Parameters []*Param
}

// NewRequestInfo creates a new RequestInfo instance with default values.
// Equivalent to creating a new dz8 object in Burp Suite.
func NewRequestInfo() *RequestInfo {
	return &RequestInfo{
		Headers:     make([]string, 0),
		Parameters:  make([]*Param, 0),
		ContentType: ContentTypeNone,
		HTTPVersion: 11, // Default to HTTP/1.1
	}
}

// Header finds and returns a specific header value by name (case-insensitive).
// Returns empty string if header is not found.
func (ri *RequestInfo) Header(name string) string {
	if len(ri.Headers) == 0 {
		return ""
	}

	// Skip the first line (request line) and search headers
	for i := 1; i < len(ri.Headers); i++ {
		header := ri.Headers[i]
		// Find the colon separator
		colonIdx := -1
		for j := 0; j < len(header); j++ {
			if header[j] == ':' {
				colonIdx = j
				break
			}
		}
		if colonIdx == -1 {
			continue
		}

		headerName := header[:colonIdx]
		// Case-insensitive comparison
		if equalsCaseInsensitive(headerName, name) {
			// Return value after colon and optional leading space
			value := header[colonIdx+1:]
			if len(value) > 0 && value[0] == ' ' {
				return value[1:]
			}
			return value
		}
	}

	return ""
}

// Parameter finds and returns a specific parameter by name.
// Returns nil if parameter is not found.
func (ri *RequestInfo) Parameter(name string) *Param {
	if ri.Parameters == nil {
		return nil
	}

	for _, param := range ri.Parameters {
		if param.Name() == name {
			return param
		}
	}

	return nil
}

// HasParameter checks if a parameter with the given name exists.
func (ri *RequestInfo) HasParameter(name string) bool {
	return ri.Parameter(name) != nil
}

// ParametersByType returns all parameters of a specific type.
func (ri *RequestInfo) ParametersByType(paramType ParamType) []*Param {
	if ri.Parameters == nil {
		return nil
	}

	result := make([]*Param, 0)
	for _, param := range ri.Parameters {
		if param.Type() == paramType {
			result = append(result, param)
		}
	}

	return result
}

// equalsCaseInsensitive performs case-insensitive string comparison.
// Helper function for header name matching.
func equalsCaseInsensitive(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i := 0; i < len(s1); i++ {
		c1 := s1[i]
		c2 := s2[i]

		// Convert to lowercase if uppercase ASCII letter
		if c1 >= 'A' && c1 <= 'Z' {
			c1 = c1 + ('a' - 'A')
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 = c2 + ('a' - 'A')
		}

		if c1 != c2 {
			return false
		}
	}

	return true
}
