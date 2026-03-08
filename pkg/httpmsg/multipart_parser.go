package httpmsg

// multipart_parser.go - Multipart/form-data parser ported from Burp Suite
// Ported from: burp/c9s.java (MULTIPART parameter parsing, lines 125-230)
//              burp/e8k.java (Multipart boundary handling)
//              burp/dz8.java (Request analysis integration)
//              burp/ap1.java (Parameter structure with MULTIPART_ATTR type)

import (
	"fmt"
	"strings"
)

// Byte patterns for multipart parsing (from c9s.java lines 9-10)
var (
	// namePattern = []byte{110, 97, 109, 101, 61, 34} = "name=\""
	namePattern = []byte("name=\"")

	// filenamePattern = []byte{102, 105, 108, 101, 110, 97, 109, 101, 61, 34} = "filename=\""
	filenamePattern = []byte("filename=\"")
)

// ParseMultipartBody parses multipart/form-data body and extracts parameters.
// This is the main entry point for multipart parsing.
//
// Ported from: c9s.java method a() for MULTIPART parsing (lines 125-230)
//
//	Case 2 in switch statement (line 125)
//
// Algorithm (from c9s.java lines 125-230):
//  1. Extract boundary from Content-Type header
//  2. Construct boundary markers: "--boundary" for parts, "--boundary--" for end
//  3. Find all boundary positions using loop-based search
//  4. For each part between boundaries:
//     - Search for "name=\"" and extract name attribute (lines 142-152)
//     - Search for "filename=\"" and extract filename if present (lines 156-163)
//     - Find end of headers (double newline sequence) (lines 166-189)
//     - Extract value content between headers and next boundary (lines 190-218)
//     - Create Parameter with type BODY_PARAM_MULTIPART (line 216-218)
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

	// Construct boundary markers (Burp uses raw byte concatenation)
	// From c9s.java line 132: boundary bytes are extracted and used directly
	boundaryBytes := []byte(boundary)

	// Parse all multipart parts
	// From c9s.java lines 136-223
	params := []*Param{}
	requestLen := len(request)
	offset := bodyOffset

	// Loop through all parts (from c9s.java lines 137-223)
	for offset < requestLen {
		// Search for "name=\"" pattern (cec.a method call at line 142)
		// This finds the start of the name attribute
		nameStart := IndexOfBytes(request, namePattern, offset)
		if nameStart == -1 {
			// No more parts found
			break
		}

		// Extract name value (from c9s.java lines 147-152)
		// nameStart points to "name=\"", so name value starts after the pattern
		nameValueStart := nameStart + len(namePattern)

		// Find closing quote for name (cec.b method call at line 148)
		// Searches for byte 34 which is '"'
		nameValueEnd := IndexOfByte(request, byte(34), nameValueStart)
		if nameValueEnd == -1 {
			// Malformed - no closing quote
			break
		}

		// Update offset to continue searching
		offset = nameValueEnd + 1

		// Find end of current line to search for filename (from c9s.java line 154)
		// cec.b(var1, (byte)10, var36, var3) searches for LF (byte 10)
		lineEnd := IndexOfByte(request, LF, nameValueStart)
		if lineEnd <= 0 {
			// Malformed - no line ending
			break
		}

		// Search for "filename=\"" in the same header line (from c9s.java lines 156-163)
		// This is optional - only present for file uploads
		var filenameParam *Param
		filenameStart := IndexOfBytes(request, filenamePattern, offset)
		if filenameStart > 0 && filenameStart < lineEnd {
			// Found filename attribute
			filenameValueStart := filenameStart + len(filenamePattern)
			filenameValueEnd := IndexOfByte(request, byte(34), filenameValueStart)
			if filenameValueEnd > 0 && filenameValueEnd < lineEnd {
				// Create filename parameter (from c9s.java line 161)
				// Type: ParamMultipartAttr, Name: "filename", Value: extracted value
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

		// Find end of headers (from c9s.java lines 166-189)
		// Look for double newline sequence (LF LF or CRLF CRLF)
		// The algorithm tracks when we see consecutive newlines
		headerEnd := offset
		sawNewline := false

		for headerEnd < requestLen {
			currentByte := request[headerEnd]

			// Check if byte is printable (>= 32) (from c9s.java line 169)
			if currentByte >= 32 {
				sawNewline = false
			}

			// Check if byte is LF (10) (from c9s.java line 173)
			if currentByte != LF {
				headerEnd++
				continue
			}

			// Found LF - check if we saw one before (from c9s.java line 180)
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

		// Value starts after the double newline (from c9s.java line 195)
		headerEnd++ // Move past the second LF
		valueStart := headerEnd

		// Find next boundary to determine value end (from c9s.java line 196)
		// cec.a(var1, var10, true, var30, var3) searches for boundary bytes
		valueEnd := IndexOfBytes(request, boundaryBytes, valueStart)
		if valueEnd == -1 || valueEnd > requestLen {
			valueEnd = requestLen
		}

		// Trim trailing CRLF/LF from value (from c9s.java lines 201-214)
		// Work backwards to remove trailing whitespace
		for valueEnd-1 > valueStart && request[valueEnd-1] != LF && request[valueEnd-1] != CR {
			valueEnd--
		}

		// Remove trailing LF if present (from c9s.java line 208)
		if valueEnd-1 > valueStart && request[valueEnd-1] == LF {
			valueEnd--
		}

		// Remove trailing CR if present (from c9s.java line 212)
		if valueEnd-1 >= valueStart && request[valueEnd-1] == CR {
			valueEnd--
		}

		// Extract name and value strings
		name := string(SliceBytes(request, nameValueStart, nameValueEnd))
		value := string(SliceBytes(request, valueStart, valueEnd))

		// Extract metadata (additional headers between name and value)
		// From c9s.java line 217: var1.a(var40 + 1, var46 - 1).x().trim()
		// This is the content between closing quote of name and start of value
		metadataStart := nameValueEnd + 1
		metadataEnd := valueStart - 1
		metadata := ""
		if metadataEnd > metadataStart {
			metadata = strings.TrimSpace(string(SliceBytes(request, metadataStart, metadataEnd)))
		}

		// Create parameter (from c9s.java lines 216-218)
		// Constructor: new ap1(var0, name, value, nameStart, nameEnd, valueStart, valueEnd, metadata)
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

		// Move offset to next part (from c9s.java line 220)
		offset = valueEnd
	}

	return params, nil
}

// ExtractBoundary extracts the boundary string from a Content-Type header value.
//
// Ported from: c9s.java lines 126-132
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

	// From c9s.java line 126: var9 = var5.indexOf("boundary=")
	boundaryPrefix := "boundary="
	idx := strings.Index(contentType, boundaryPrefix)
	if idx == -1 {
		return ""
	}

	// From c9s.java line 131: var5.substring(var9).trim()
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
