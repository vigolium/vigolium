package httpmsg

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"strings"
)

// ParameterFormat represents the detected content format of a parameter value.
// Follows Burp's h5p enum for format classification.
type ParameterFormat int

const (
	// FormatNone indicates no structured format detected
	FormatNone ParameterFormat = iota
	// FormatJSON indicates JSON object or array format
	FormatJSON
	// FormatXML indicates XML document format
	FormatXML
	// FormatURLEncoded indicates URL-encoded key-value pairs
	FormatURLEncoded
	// FormatBase64 indicates Base64-encoded data
	FormatBase64
)

// String returns the string representation of the format
func (f ParameterFormat) String() string {
	switch f {
	case FormatJSON:
		return "JSON"
	case FormatXML:
		return "XML"
	case FormatURLEncoded:
		return "URLEncoded"
	case FormatBase64:
		return "Base64"
	default:
		return "None"
	}
}

// DetectParameterFormat analyzes a parameter value to detect if it contains
// a nested structure (JSON, XML, Base64, or URL-encoded data).
//
// This follows Burp Suite's rp.java format detection logic (lines 12-40),
// which uses structural markers to identify content types:
//   - JSON: starts with { or [, ends with } or ]
//   - XML: starts with <, ends with >
//   - Base64: matches Base64 alphabet with valid padding
//   - URL-encoded: contains %XX sequences or name=value patterns
//
// The detection is conservative to avoid false positives.
func DetectParameterFormat(value string) ParameterFormat {
	// Trim whitespace (Burp's rp.java uses by9.a() to trim)
	trimmed := strings.TrimSpace(value)
	if len(trimmed) == 0 {
		return FormatNone
	}

	first := trimmed[0]
	last := trimmed[len(trimmed)-1]

	// Check for JSON object: {...}
	// Burp's rp.java line 23-25
	if first == '{' && last == '}' {
		// Verify it's valid JSON to avoid false positives
		var data map[string]interface{}
		if json.Unmarshal([]byte(trimmed), &data) == nil {
			return FormatJSON
		}
	}

	// Check for JSON array: [...]
	// Burp's rp.java line 26-28
	if first == '[' && last == ']' {
		// Verify it's valid JSON
		var data []interface{}
		if json.Unmarshal([]byte(trimmed), &data) == nil {
			return FormatJSON
		}
	}

	// Check for XML: <...>
	// Burp's rp.java line 19-21
	if first == '<' && last == '>' {
		// Basic XML validation
		if strings.Contains(trimmed, "</") || strings.HasSuffix(trimmed, "/>") {
			// Try to parse as XML
			if err := xml.Unmarshal([]byte(trimmed), new(interface{})); err == nil {
				return FormatXML
			}
		}
	}

	// Check for Base64 encoding
	// Burp doesn't have explicit Base64 detection in rp.java, but it's useful for nested discovery
	if isValidBase64(trimmed) {
		return FormatBase64
	}

	// Check for URL-encoded data
	// Burp's detection is implicit through URL_ENCODED type
	if containsURLEncoding(trimmed) {
		return FormatURLEncoded
	}

	return FormatNone
}

// isValidBase64 checks if a string is valid Base64-encoded data.
// Base64 alphabet: A-Z, a-z, 0-9, +, /, = (padding)
// Must be at least 4 characters and have valid padding structure.
func isValidBase64(s string) bool {
	// Too short to be meaningful Base64
	if len(s) < 4 {
		return false
	}

	// Check each character is in Base64 alphabet
	for _, c := range s {
		isUpperAlpha := c >= 'A' && c <= 'Z'
		isLowerAlpha := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isSpecial := c == '+' || c == '/' || c == '='
		if !isUpperAlpha && !isLowerAlpha && !isDigit && !isSpecial {
			return false
		}
	}

	// Validate padding structure (= can only appear at end)
	paddingIndex := strings.IndexByte(s, '=')
	if paddingIndex != -1 {
		// Padding must be in last 2 positions
		if paddingIndex < len(s)-2 {
			return false
		}
		// After first =, only = allowed
		for i := paddingIndex + 1; i < len(s); i++ {
			if s[i] != '=' {
				return false
			}
		}
	}

	// Try to decode to confirm it's valid Base64
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// containsURLEncoding checks if a string contains URL-encoded patterns.
// Looks for:
//   - %XX hex sequences (URL percent-encoding)
//   - name=value&name=value patterns (query string format)
func containsURLEncoding(s string) bool {
	// Check for %XX hex sequences
	hasPercent := false
	for i := 0; i < len(s)-2; i++ {
		if s[i] == '%' {
			if isHexDigit(s[i+1]) && isHexDigit(s[i+2]) {
				hasPercent = true
				break
			}
		}
	}

	// Check for query string pattern: name=value&name=value
	hasQueryPattern := false
	if strings.Contains(s, "=") {
		// Must have either & separator or be a single param
		if strings.Contains(s, "&") {
			// Multiple params
			hasQueryPattern = true
		} else {
			// Single param - check if it looks like name=value
			parts := strings.SplitN(s, "=", 2)
			if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
				// Make sure name doesn't contain suspicious characters
				name := parts[0]
				validName := true
				for _, c := range name {
					isLowerAlpha := c >= 'a' && c <= 'z'
					isUpperAlpha := c >= 'A' && c <= 'Z'
					isDigit := c >= '0' && c <= '9'
					isSpecial := c == '_' || c == '-' || c == '.'
					if !isLowerAlpha && !isUpperAlpha && !isDigit && !isSpecial {
						validName = false
						break
					}
				}
				if validName {
					hasQueryPattern = true
				}
			}
		}
	}

	// Consider it URL-encoded if it has percent encoding OR query pattern
	return hasPercent || hasQueryPattern
}

// isHexDigit checks if a byte is a hexadecimal digit (0-9, A-F, a-f)
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f')
}
