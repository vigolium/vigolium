package httpmsg

import (
	"strings"
)

// HttpHeader represents an HTTP header with name and value.
type HttpHeader struct {
	Name  string
	Value string
}

// NewHttpHeader creates a new HttpHeader with the given name and value.
func NewHttpHeader(name, value string) HttpHeader {
	return HttpHeader{Name: name, Value: value}
}

// ParseHttpHeader parses a header line in "Name: Value" format.
// Returns empty HttpHeader if the line is invalid.
func ParseHttpHeader(line string) HttpHeader {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return HttpHeader{}
	}
	name := line[:idx]
	value := ""
	if idx+1 < len(line) {
		value = strings.TrimLeft(line[idx+1:], " ")
	}
	return HttpHeader{Name: name, Value: value}
}

// String returns the header as "Name: Value" format.
func (h HttpHeader) String() string {
	return h.Name + ": " + h.Value
}

// FindHttpHeader searches for a header by name (case-insensitive) in a slice of headers.
// Returns the value and true if found, empty string and false otherwise.
func FindHttpHeader(headers []HttpHeader, name string) (string, bool) {
	nameLower := strings.ToLower(name)
	for _, h := range headers {
		if strings.ToLower(h.Name) == nameLower {
			return h.Value, true
		}
	}
	return "", false
}

// HttpHeadersContain checks if headers contain a header with the given name (case-insensitive).
func HttpHeadersContain(headers []HttpHeader, name string) bool {
	_, found := FindHttpHeader(headers, name)
	return found
}

// SetHttpHeader returns a new headers slice with the header added or updated.
// If a header with the same name exists, it will be replaced.
func SetHttpHeader(headers []HttpHeader, name, value string) []HttpHeader {
	nameLower := strings.ToLower(name)
	result := make([]HttpHeader, 0, len(headers)+1)
	found := false

	for _, h := range headers {
		if strings.ToLower(h.Name) == nameLower {
			result = append(result, HttpHeader{Name: name, Value: value})
			found = true
		} else {
			result = append(result, h)
		}
	}

	if !found {
		result = append(result, HttpHeader{Name: name, Value: value})
	}

	return result
}

// AppendHttpHeader returns a new headers slice with the header appended.
// Does not check for duplicates - adds unconditionally.
func AppendHttpHeader(headers []HttpHeader, name, value string) []HttpHeader {
	result := make([]HttpHeader, len(headers)+1)
	copy(result, headers)
	result[len(headers)] = HttpHeader{Name: name, Value: value}
	return result
}

// RemoveHttpHeader returns a new headers slice with all headers of the given name removed.
func RemoveHttpHeader(headers []HttpHeader, name string) []HttpHeader {
	nameLower := strings.ToLower(name)
	result := make([]HttpHeader, 0, len(headers))

	for _, h := range headers {
		if strings.ToLower(h.Name) != nameLower {
			result = append(result, h)
		}
	}

	return result
}

// CloneHttpHeaders creates a deep copy of the headers slice.
func CloneHttpHeaders(headers []HttpHeader) []HttpHeader {
	if headers == nil {
		return nil
	}
	result := make([]HttpHeader, len(headers))
	copy(result, headers)
	return result
}

// ParseHeadersFromStrings converts a slice of header strings to HttpHeader slice.
// Skips the first line (request/status line) automatically.
func ParseHeadersFromStrings(headerStrings []string) []HttpHeader {
	if len(headerStrings) <= 1 {
		return nil
	}
	result := make([]HttpHeader, 0, len(headerStrings)-1)
	for i := 1; i < len(headerStrings); i++ {
		h := ParseHttpHeader(headerStrings[i])
		if h.Name != "" {
			result = append(result, h)
		}
	}
	return result
}

// HeadersToStrings converts HttpHeader slice to string slice.
// Useful for rebuilding raw HTTP messages.
func HeadersToStrings(headers []HttpHeader) []string {
	result := make([]string, len(headers))
	for i, h := range headers {
		result[i] = h.String()
	}
	return result
}
