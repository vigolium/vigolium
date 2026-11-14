package anomaly

import "golang.org/x/net/html"

// ExtractAttributesFromRaw extracts attributes from raw response components.
// Useful when you already have the response data extracted.
func ExtractAttributesFromRaw(statusCode int, body string, headers map[string][]string) (*AttributeSet, error) {
	return ExtractAttributesFromRawDoc(statusCode, body, headers, nil)
}

// ExtractAttributesFromRawDoc is ExtractAttributesFromRaw reusing an
// already-parsed HTML document of body (nil parses as usual).
func ExtractAttributesFromRawDoc(statusCode int, body string, headers map[string][]string, doc *html.Node) (*AttributeSet, error) {
	// Use webfinger to extract all attributes
	fp := NewFingerprint(AllFingerprintAttributes)
	fp.UpdateWithDocument(statusCode, body, headers, doc)

	// Create AttributeSet and populate it
	attrs := NewAttributeSet()
	for _, attrType := range AllFingerprintAttributes {
		if value, ok := fp.GetAttributeValue(attrType); ok && value != 0 {
			attrs.Set(attrType, value)
		}
	}

	return attrs, nil
}
