package httpmsg

// multipart_parser.go - Multipart/form-data parser

import (
	"fmt"
	"strings"
)

// Byte patterns for multipart parsing
var (
	// namePattern = []byte{110, 97, 109, 101, 61, 34} = "name=\""
	namePattern = []byte("name=\"")

	// filenamePattern = []byte{102, 105, 108, 101, 110, 97, 109, 101, 61, 34} = "filename=\""
	filenamePattern = []byte("filename=\"")
)

// ParseMultipartBody parses multipart/form-data body and extracts parameters.
// This is the main entry point for multipart parsing.
//
// Algorithm:
//  1. Extract boundary from Content-Type header
//  2. Construct boundary markers: "--boundary" for parts, "--boundary--" for end
//  3. Find all boundary positions using loop-based search
//  4. For each part between boundaries:
//     - Search for "name=\"" and extract name attribute
//     - Search for "filename=\"" and extract filename if present
//     - Find end of headers (double newline sequence)
//     - Extract value content between headers and next boundary
//     - Create Parameter with type BODY_PARAM_MULTIPART
//  5. Track all byte offsets relative to request start
//
// Example:
//
//	request := []byte("POST / HTTP/1.1\r\n" +
//	    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n\r\n" +
//	    "------WebKitFormBoundary\r\n" +
//	    "Content-Disposition: form-data; name=\"field\"\r\n\r\n" +
//	    "value\r\n" +
//	    "------WebKitFormBoundary--")
//
//	bodyOffset := FindBodyOffset(request)
//	params, err := ParseMultipartBody(request, bodyOffset, "----WebKitFormBoundary")
//	// Returns: []*Param with ParamBodyMultipart type
//
// Parameters:
//   - request: Full HTTP request bytes
//   - bodyOffset: Position where body starts (after headers)
//   - boundary: Boundary string from Content-Type header
//
// Returns:
//   - List of Param objects with ParamBodyMultipart type
//   - Error if boundary is empty or parsing fails
func ParseMultipartBody(request []byte, bodyOffset int, boundary string) ([]*Param, error) {
	if boundary == "" {
		return nil, fmt.Errorf("boundary required for multipart parsing")
	}

	if request == nil || bodyOffset < 0 || bodyOffset >= len(request) {
		return []*Param{}, nil
	}

	// Construct boundary markers
	boundaryBytes := []byte(boundary)

	// Parse all multipart parts
	params := []*Param{}
	requestLen := len(request)
	offset := bodyOffset

	// Loop through all parts
	for offset < requestLen {
		// Search for "name=\"" pattern to find the start of the name attribute
		nameStart := IndexOfBytes(request, namePattern, offset)
		if nameStart == -1 {
			// No more parts found
			break
		}

		// Extract name value
		// nameStart points to "name=\"", so name value starts after the pattern
		nameValueStart := nameStart + len(namePattern)

		// Find closing quote for name (byte 34 = '"')
		nameValueEnd := IndexOfByte(request, byte(34), nameValueStart)
		if nameValueEnd == -1 {
			// Malformed - no closing quote
			break
		}

		// Update offset to continue searching
		offset = nameValueEnd + 1

		// Find end of current line to search for filename
		lineEnd := IndexOfByte(request, LF, nameValueStart)
		if lineEnd <= 0 {
			// Malformed - no line ending
			break
		}

		// Search for "filename=\"" in the same header line
		// This is optional - only present for file uploads
		var filenameParam *Param
		filenameStart := IndexOfBytes(request, filenamePattern, offset)
		if filenameStart > 0 && filenameStart < lineEnd {
			// Found filename attribute
			filenameValueStart := filenameStart + len(filenamePattern)
			filenameValueEnd := IndexOfByte(request, byte(34), filenameValueStart)
			if filenameValueEnd > 0 && filenameValueEnd < lineEnd {
				// Create filename parameter (ParamMultipartAttr type)
				filenameValue := string(SliceBytes(request, filenameValueStart, filenameValueEnd))
				filenameParam = NewParsedParam(
					ParamMultipartAttr,
					"filename",
					filenameValue,
					filenameStart,        // nameStart: points to "filename="
					filenameValueStart-2, // nameEnd: points to position before quote
					filenameValueStart,   // valueStart: after opening quote
					filenameValueEnd,     // valueEnd: at closing quote
				)
			}
		}

		// Find end of headers
		// Look for double newline sequence (LF LF or CRLF CRLF)
		headerEnd := offset
		sawNewline := false

		for headerEnd < requestLen {
			currentByte := request[headerEnd]

			// Check if byte is printable (>= 32)
			if currentByte >= 32 {
				sawNewline = false
			}

			// Check if byte is LF (10)
			if currentByte != LF {
				headerEnd++
				continue
			}

			// Found LF - check if we saw one before
			if sawNewline {
				// Double newline found - headers end here
				break
			}

			sawNewline = true
			headerEnd++
		}

		// Check if we reached end without finding header end
		if headerEnd >= requestLen {
			break
		}

		// Value starts after the double newline
		headerEnd++ // Move past the second LF
		valueStart := headerEnd

		// Find next boundary to determine value end
		valueEnd := IndexOfBytes(request, boundaryBytes, valueStart)
		if valueEnd == -1 || valueEnd > requestLen {
			valueEnd = requestLen
		}

		// Trim trailing CRLF/LF from value (work backwards)
		for valueEnd-1 > valueStart && request[valueEnd-1] != LF && request[valueEnd-1] != CR {
			valueEnd--
		}

		// Remove trailing LF if present
		if valueEnd-1 > valueStart && request[valueEnd-1] == LF {
			valueEnd--
		}

		// Remove trailing CR if present
		if valueEnd-1 >= valueStart && request[valueEnd-1] == CR {
			valueEnd--
		}

		// Extract name and value strings
		name := string(SliceBytes(request, nameValueStart, nameValueEnd))
		value := string(SliceBytes(request, valueStart, valueEnd))

		// Extract metadata (additional headers between name and value)
		// This is the content between closing quote of name and start of value
		metadataStart := nameValueEnd + 1
		metadataEnd := valueStart - 1
		metadata := ""
		if metadataEnd > metadataStart {
			metadata = strings.TrimSpace(string(SliceBytes(request, metadataStart, metadataEnd)))
		}

		// Create parameter
		param := NewParsedParamWithMetadata(
			ParamBodyMultipart,
			name,
			value,
			nameValueStart, // nameStart: start of name value
			nameValueEnd,   // nameEnd: end of name value
			valueStart,     // valueStart: start of value content
			valueEnd,       // valueEnd: end of value content
			metadata,       // metadata: headers between name and value
		)

		params = append(params, param)

		// Add filename parameter if present
		if filenameParam != nil {
			params = append(params, filenameParam)
		}

		// Move offset to next part
		offset = valueEnd
	}

	return params, nil
}

// ExtractBoundary extracts the boundary string from a Content-Type header value.
//
// Algorithm:
//  1. Search for "boundary=" in Content-Type header
//  2. Extract everything after "boundary="
//  3. Trim whitespace
//  4. Return boundary string
//
// Example:
//
//	contentType := "multipart/form-data; boundary=----WebKitFormBoundary1234"
//	boundary := ExtractBoundary(contentType)
//	// Returns: "----WebKitFormBoundary1234"
//
// Parameters:
//   - contentType: Content-Type header value
//
// Returns:
//   - Boundary string, or empty string if not found
func ExtractBoundary(contentType string) string {
	if contentType == "" {
		return ""
	}

	boundaryPrefix := "boundary="
	idx := strings.Index(contentType, boundaryPrefix)
	if idx == -1 {
		return ""
	}

	idx += len(boundaryPrefix)
	boundary := strings.TrimSpace(contentType[idx:])

	return boundary
}

// ParseMultipartRequest is a convenience function that extracts the boundary
// from headers and parses the multipart body in one call.
//
// This combines boundary extraction and multipart parsing.
//
// Algorithm:
//  1. Find Content-Type header in request
//  2. Extract boundary from Content-Type
//  3. Find body offset
//  4. Call ParseMultipartBody with extracted boundary
//
// Example:
//
//	request := []byte("POST / HTTP/1.1\r\n" +
//	    "Content-Type: multipart/form-data; boundary=----WebKit\r\n\r\n" +
//	    "------WebKit\r\n" +
//	    "Content-Disposition: form-data; name=\"field\"\r\n\r\n" +
//	    "value\r\n" +
//	    "------WebKit--")
//
//	params, err := ParseMultipartRequest(request)
//	// Automatically extracts boundary and parses body
//
// Parameters:
//   - request: Full HTTP request bytes
//
// Returns:
//   - List of Param objects with ParamBodyMultipart type
//   - Error if Content-Type not found or parsing fails
func ParseMultipartRequest(request []byte) ([]*Param, error) {
	if request == nil {
		return nil, fmt.Errorf("request is nil")
	}

	// Find Content-Type header
	contentType := extractHeader(request, "Content-Type")
	if contentType == "" {
		return nil, fmt.Errorf("Content-Type header not found")
	}

	// Extract boundary
	boundary := ExtractBoundary(contentType)
	if boundary == "" {
		return nil, fmt.Errorf("boundary not found in Content-Type header")
	}

	// Find body offset
	bodyOffset := FindBodyOffset(request)

	// Parse multipart body
	return ParseMultipartBody(request, bodyOffset, boundary)
}

// extractHeader extracts a header value from an HTTP request.
// This is a helper function for ParseMultipartRequest.
//
// Algorithm:
//  1. Search for header name followed by ':'
//  2. Extract value until end of line
//  3. Trim whitespace
//
// Parameters:
//   - request: HTTP request bytes
//   - headerName: Name of header to extract (case-insensitive)
//
// Returns:
//   - Header value, or empty string if not found
func extractHeader(request []byte, headerName string) string {
	if request == nil || headerName == "" {
		return ""
	}

	// Convert to bytes for searching
	searchPattern := []byte(headerName + ":")

	// Find header (case-insensitive search would be better, but keep it simple)
	headerStart := IndexOfBytes(request, searchPattern, 0)
	if headerStart == -1 {
		// Try lowercase
		searchPattern = []byte(strings.ToLower(headerName) + ":")
		headerStart = IndexOfBytes(request, searchPattern, 0)
		if headerStart == -1 {
			return ""
		}
	}

	// Find start of value (after ':' and whitespace)
	valueStart := headerStart + len(searchPattern)
	for valueStart < len(request) && (request[valueStart] == ' ' || request[valueStart] == '\t') {
		valueStart++
	}

	// Find end of line
	valueEnd := IndexOfByte(request, LF, valueStart)
	if valueEnd == -1 {
		valueEnd = len(request)
	}

	// Trim trailing CR if present
	if valueEnd > valueStart && request[valueEnd-1] == CR {
		valueEnd--
	}

	return strings.TrimSpace(string(SliceBytes(request, valueStart, valueEnd)))
}
