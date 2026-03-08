package anomaly

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// ExtractAttributes extracts attribute values from an HTTP response.
// This function reads the response body once, extracts all attributes,
// and returns an AttributeSet containing only the extracted values (132 bytes).
//
// The response body can be safely garbage collected after this call,
// making this function memory-efficient for large-scale processing.
//
// If you need to preserve the response body for later use, store it in
// the ResponseRecord.Metadata field.
func ExtractAttributes(resp *http.Response) (*AttributeSet, error) {
	if resp == nil {
		return nil, fmt.Errorf("http.Response is nil")
	}

	// Read body
	var body string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		body = string(bodyBytes)
		// Reset body for future reads
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Extract attributes using webfinger
	return ExtractAttributesFromRaw(resp.StatusCode, body, resp.Header)
}

// ExtractAttributesFromRaw extracts attributes from raw response components.
// Useful when you already have the response data extracted.
func ExtractAttributesFromRaw(statusCode int, body string, headers map[string][]string) (*AttributeSet, error) {
	// Use webfinger to extract all attributes
	fp := NewFingerprint(AllFingerprintAttributes)
	fp.UpdateWith(statusCode, body, headers)

	// Create AttributeSet and populate it
	attrs := NewAttributeSet()
	for _, attrType := range AllFingerprintAttributes {
		if value, ok := fp.GetAttributeValue(attrType); ok && value != 0 {
			attrs.Set(attrType, value)
		}
	}

	return attrs, nil
}
