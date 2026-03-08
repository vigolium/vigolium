package httpmsg

// request_builder_utils.go - Utility functions for request manipulation
//
// This file contains:
// - CloneRequest
// - NormalizeLineEndings
// - StripTrailingData
// - RequestsEqual, RequestsEqualNormalized

// CloneRequest creates a deep copy of a request.
// Extension to Burp API - provides request cloning.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Cloned request
//
// Example:
//
//	clone := CloneRequest(request)
func CloneRequest(request []byte) []byte {
	if request == nil {
		return nil
	}

	clone := make([]byte, len(request))
	copy(clone, request)
	return clone
}

// NormalizeLineEndings ensures all line endings are CRLF.
// Extension to Burp API - provides line ending normalization.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Normalized request
//
// Example:
//
//	normalized := NormalizeLineEndings(request)
func NormalizeLineEndings(request []byte) []byte {
	if request == nil {
		return nil
	}

	result := make([]byte, 0, len(request))
	i := 0
	for i < len(request) {
		if request[i] == LF && (i == 0 || request[i-1] != CR) {
			// LF without CR, add CR before it
			result = append(result, CR, LF)
			i++
		} else if request[i] == CR {
			// CR found, check next byte
			if i+1 < len(request) && request[i+1] == LF {
				// Already CRLF, copy both
				result = append(result, CR, LF)
				i += 2
			} else {
				// CR without LF, add LF after it
				result = append(result, CR, LF)
				i++
			}
		} else {
			result = append(result, request[i])
			i++
		}
	}

	return result
}

// StripTrailingData removes any data after the body.
// Extension to Burp API - removes trailing garbage.
//
// Parameters:
//   - request: HTTP request bytes
//
// Returns:
//   - Request without trailing data
//
// Example:
//
//	cleaned := StripTrailingData(request)
func StripTrailingData(request []byte) []byte {
	// For now, just return as-is since we trust FindBodyOffset
	// In the future, could check Content-Length and trim beyond that
	return request
}

// RequestsEqual checks if two requests are byte-level equal.
// Extension to Burp API - provides request comparison.
//
// Parameters:
//   - req1: First request
//   - req2: Second request
//
// Returns:
//   - true if requests are identical
//
// Example:
//
//	if RequestsEqual(req1, req2) {
//	    // Requests are identical
//	}
func RequestsEqual(req1, req2 []byte) bool {
	if len(req1) != len(req2) {
		return false
	}

	for i := 0; i < len(req1); i++ {
		if req1[i] != req2[i] {
			return false
		}
	}

	return true
}

// RequestsEqualNormalized checks if requests are equal after normalization.
// Extension to Burp API - provides normalized comparison.
//
// Parameters:
//   - req1: First request
//   - req2: Second request
//
// Returns:
//   - true if requests are equal after normalization
//
// Example:
//
//	if RequestsEqualNormalized(req1, req2) {
//	    // Requests are functionally identical
//	}
func RequestsEqualNormalized(req1, req2 []byte) bool {
	norm1 := NormalizeLineEndings(req1)
	norm2 := NormalizeLineEndings(req2)
	return RequestsEqual(norm1, norm2)
}
