package httpmsg

// JSON Parameter Extractor
//
// Character-by-character JSON parser that tracks byte offsets.
//
// Design:
//   - No JSON library is used
//   - Manual character-by-character parsing to track byte offsets
//   - Returns offsets to RAW JSON (with escape sequences intact)
//   - Using json.Unmarshal then searching for decoded values would fail
//
// Algorithm:
//  1. Manual state machine parsing (no JSON library)
//  2. Track position index
//  3. Parse structure characters: { } [ ] : , "
//  4. Handle escape sequences: when \ found, skip next character
//  5. Return raw byte offsets pointing to content in original JSON

import (
	"fmt"
	"strconv"
)

// jsonParser is the state machine for character-by-character JSON parsing.
type jsonParser struct {
	data       []byte   // Raw JSON bytes
	pos        int      // Current position
	end        int      // End position
	baseOffset int      // Offset to adjust for position in full request
	params     []*Param // Collected parameters
	path       string   // Current JSON path (for metadata)
}

// ParseJSONBody parses application/json body and extracts parameters.
//
// Algorithm:
//  1. Create parser instance with data range
//  2. Call parseValue to start parsing from root
//  3. Return collected parameters
//
// Parameters:
//   - request: Full HTTP request bytes OR just JSON bytes
//   - bodyOffset: Starting position of JSON in request (0 if request IS the JSON)
//
// Returns:
//   - List of parameters with JSON paths and byte offsets
//   - Error if JSON structure is invalid
func ParseJSONBody(request []byte, bodyOffset int) ([]*Param, error) {
	if bodyOffset >= len(request) {
		return nil, fmt.Errorf("bodyOffset %d >= request length %d", bodyOffset, len(request))
	}

	body := request[bodyOffset:]
	if len(body) == 0 {
		return []*Param{}, nil
	}

	// Create parser
	p := &jsonParser{
		data:       body,
		pos:        0,
		end:        len(body),
		baseOffset: bodyOffset,
		params:     make([]*Param, 0),
		path:       "",
	}

	// Start parsing from root value
	if err := p.parseValue(nil, 0); err != nil {
		return []*Param{}, nil // Return empty list on parse errors
	}

	return p.params, nil
}

// parseValue parses a JSON value at current position.
//
// Algorithm:
//  1. Skip whitespace
//  2. Check first character:
//     - " → Parse quoted string
//     - [ → Parse array
//     - { → Parse object
//     - Other → Parse unquoted value (number, boolean, null)
//
// Parameters:
//   - keyOffsets: Offsets of the key for this value (nil for root/array elements)
//   - delimiter: Expected delimiter after value (0, 44=comma, 93=], 125=})
//
// Returns:
//   - Error if parsing fails
func (p *jsonParser) parseValue(keyOffsets []int, delimiter byte) error {
	p.skipWhitespace()

	if p.pos >= p.end {
		return fmt.Errorf("unexpected end of JSON")
	}

	switch p.data[p.pos] {
	case '"': // Quoted string value
		valueOffsets := p.parseQuotedString()
		if valueOffsets != nil && keyOffsets != nil {
			p.createParameterWithType(keyOffsets, valueOffsets, JSONTypeString)
		}
		return nil

	case '[': // Array value
		p.parseArray(keyOffsets)
		return nil

	case '{': // Object value
		p.parseObject()
		return nil

	default: // Unquoted value: number, boolean, null
		valueOffsets, valueType := p.parseUnquotedValueWithType(',', delimiter)
		if valueOffsets != nil && keyOffsets != nil {
			p.createParameterWithType(keyOffsets, valueOffsets, valueType)
		}
		return nil
	}
}

// parseObject parses a JSON object: {key1:value1, key2:value2, ...}
func (p *jsonParser) parseObject() {
	savedPath := p.path

	p.skipWhitespace()
	if p.pos >= p.end || p.data[p.pos] != '{' {
		return
	}

	p.pos++ // Skip {

	for p.pos < p.end {
		p.skipWhitespace()

		// Check for closing }
		if p.data[p.pos] == '}' {
			p.pos++
			p.path = savedPath
			return
		}

		// Parse key
		keyOffsets := p.parseQuotedString()
		if keyOffsets == nil {
			p.path = savedPath
			return
		}

		// Extract key name for path
		keyName := string(p.data[keyOffsets[0]:keyOffsets[1]])

		// Update path with this key
		if p.path == "" {
			p.path = keyName
		} else {
			p.path = p.path + "." + keyName
		}

		p.skipWhitespace()

		// Check for : separator
		if p.pos >= p.end || p.data[p.pos] != ':' {
			p.path = savedPath
			return
		}
		p.pos++ // Skip :

		// Parse value
		_ = p.parseValue(keyOffsets, '}')

		// Restore path after value
		p.path = savedPath

		p.skipWhitespace()

		// Check for , or }
		if p.pos >= p.end {
			return
		}

		switch p.data[p.pos] {
		case ',': // Continue to next key-value pair
			p.pos++
			p.skipWhitespace()
			if p.pos < p.end && p.data[p.pos] == '}' {
				p.pos++
				return
			}
		case '}': // End of object
			p.pos++
			return
		default:
			return
		}
	}
}

// parseArray parses a JSON array: [value1, value2, ...]
// Array elements share the parent key name (no indexed paths).
//
// Parameters:
//   - keyOffsets: Offsets of the key for this array (used for all elements)
func (p *jsonParser) parseArray(keyOffsets []int) {
	p.skipWhitespace()
	if p.pos >= p.end || p.data[p.pos] != '[' {
		return
	}

	p.pos++ // Skip [

	for p.pos < p.end {
		// Parse value (all array elements share the same keyOffsets/parameter name)
		_ = p.parseValue(keyOffsets, ']')

		p.skipWhitespace()

		if p.pos >= p.end {
			return
		}

		// Check for , or ]
		switch p.data[p.pos] {
		case ',': // Continue to next element
			p.pos++
			p.skipWhitespace()
			if p.pos < p.end && p.data[p.pos] == ']' {
				p.pos++
				return
			}
		case ']': // End of array
			p.pos++
			return
		default:
			return
		}
	}
}

// parseQuotedString parses a quoted JSON string and returns its byte offsets.
//
// Handles escape sequences correctly: when \ is found, the next character is skipped.
// This allows returning offsets to the RAW content in the original JSON.
//
// Returns:
//   - int[]{start, end} pointing to content (excluding quotes)
//   - nil if not a valid quoted string
func (p *jsonParser) parseQuotedString() []int {
	p.skipWhitespace()

	if p.pos >= p.end || p.data[p.pos] != '"' {
		// Not a quoted string, try unquoted (for lenient parsing)
		offsets, _ := p.parseUnquotedValueWithType(':', 0)
		return offsets
	}

	p.pos++ // Skip opening "
	start := p.pos

	end := -1
	for p.pos < p.end {
		switch p.data[p.pos] {
		case '"': // Found closing "
			end = p.pos
			p.pos++ // Move past "
			return []int{start, end}

		case '\\': // Found escape sequence
			// Skip the backslash AND the next character
			p.pos++ // Skip \
			if p.pos < p.end {
				p.pos++ // Skip escaped character
			}

		default: // Regular character
			p.pos++
		}
	}

	// String not properly closed, use end of data
	if end == -1 {
		end = p.end
	}

	return []int{start, end}
}

// parseUnquotedValueWithType parses an unquoted JSON value (number, boolean, null)
// and returns both the offsets and the detected JSON value type.
//
// Parameters:
//   - delim1: First delimiter byte (e.g., ',' for comma)
//   - delim2: Second delimiter byte (e.g., '}' for object end)
//
// Returns:
//   - int[]{start, end} pointing to value (nil if empty)
//   - JSONValueType indicating the detected type
func (p *jsonParser) parseUnquotedValueWithType(delim1, delim2 byte) ([]int, JSONValueType) {
	start := p.pos
	end := -1

	for p.pos < p.end {
		b := p.data[p.pos]

		// Check for end conditions: whitespace or delimiters
		if b <= 32 || b == delim1 || b == delim2 {
			end = p.pos
			break
		}

		p.pos++
	}

	// If no terminator found, use end of data
	if end == -1 {
		end = p.end
	}

	// Return nil if empty value
	if start == end {
		return nil, JSONTypeUnknown
	}

	// Detect value type from raw content
	raw := string(p.data[start:end])
	valueType := detectJSONValueType(raw)

	return []int{start, end}, valueType
}

// detectJSONValueType determines the JSON value type from raw content.
func detectJSONValueType(raw string) JSONValueType {
	switch raw {
	case "true", "false":
		return JSONTypeBool
	case "null":
		return JSONTypeNull
	default:
		if isJSONNumber(raw) {
			return JSONTypeNumber
		}
		return JSONTypeUnknown
	}
}

// isJSONNumber checks if a string is a valid JSON number.
// Supports integers, floats, negative numbers, and scientific notation.
func isJSONNumber(s string) bool {
	if len(s) == 0 {
		return false
	}
	i := 0
	// Optional leading minus
	if s[0] == '-' {
		i++
	}
	if i >= len(s) {
		return false
	}
	// Must start with digit
	if s[i] < '0' || s[i] > '9' {
		return false
	}
	// Allow digits, '.', 'e', 'E', '+', '-' for the rest
	for ; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// skipWhitespace skips over whitespace characters (bytes <= 32).
func (p *jsonParser) skipWhitespace() {
	for p.pos < p.end {
		b := p.data[p.pos]
		// Non-whitespace: stop
		if b > 32 {
			break
		}
		p.pos++
	}
}

// createParameterWithType creates a Param from key and value offsets with JSON type info.
//
// Algorithm:
//  1. Extract key name from keyOffsets
//  2. Extract value from valueOffsets
//  3. Create Param with ParamJSON type and JSONValueType
//  4. Store current JSON path in Metadata field
//  5. Adjust offsets by baseOffset for full request
//
// Parameters:
//   - keyOffsets: [start, end] of key in raw JSON
//   - valueOffsets: [start, end] of value in raw JSON
//   - valueType: the detected JSON value type (string, number, bool, null)
func (p *jsonParser) createParameterWithType(keyOffsets, valueOffsets []int, valueType JSONValueType) {
	if keyOffsets == nil || valueOffsets == nil {
		return
	}

	// Extract key name (last component of path)
	keyName := string(p.data[keyOffsets[0]:keyOffsets[1]])

	// Extract value content (raw, with escapes)
	valueRaw := string(p.data[valueOffsets[0]:valueOffsets[1]])

	// Decode value for display (handle escapes, numbers, booleans)
	valueDecoded := decodeJSONValue(valueRaw)

	// Get the full JSON path for metadata
	// Use current path which was built during object parsing
	metadata := p.path
	if metadata == "" {
		metadata = keyName
	}

	// Create param using NewJSONParsedParam which sets all fields including JSONType
	param := NewJSONParsedParam(
		keyName,
		valueDecoded,
		keyOffsets[0]+p.baseOffset,
		keyOffsets[1]+p.baseOffset,
		valueOffsets[0]+p.baseOffset,
		valueOffsets[1]+p.baseOffset,
		metadata, // Full JSON path
		valueType,
	)

	p.params = append(p.params, param)
}

// decodeJSONValue decodes a JSON value for display.
// Handles JSON escape sequences and type conversion.
//
// This is needed because we store RAW offsets pointing to escaped content,
// but Parameter.Value should contain the decoded value for scanners to use.
//
// Parameters:
//   - raw: Raw JSON value string (may contain escape sequences)
//
// Returns:
//   - Decoded value string
func decodeJSONValue(raw string) string {
	if len(raw) == 0 {
		return raw
	}

	// Check if it's a string (would have quotes in full JSON, but we have content only)
	// Try to detect by checking for escape sequences
	if containsEscape(raw) {
		return unescapeJSON(raw)
	}

	// Check if it's a number
	if len(raw) > 0 && (raw[0] >= '0' && raw[0] <= '9') || raw[0] == '-' {
		return raw // Numbers don't need decoding
	}

	// Check if it's a boolean or null
	if raw == "true" || raw == "false" || raw == "null" {
		return raw
	}

	// Otherwise treat as string
	return unescapeJSON(raw)
}

// containsEscape checks if a string contains JSON escape sequences.
func containsEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			return true
		}
	}
	return false
}

// unescapeJSON unescapes JSON escape sequences in a string.
// Handles: \" \\ \/ \b \f \n \r \t \uXXXX
func unescapeJSON(s string) string {
	if !containsEscape(s) {
		return s
	}

	result := make([]byte, 0, len(s))
	i := 0

	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"':
				result = append(result, '"')
				i += 2
			case '\\':
				result = append(result, '\\')
				i += 2
			case '/':
				result = append(result, '/')
				i += 2
			case 'b':
				result = append(result, '\b')
				i += 2
			case 'f':
				result = append(result, '\f')
				i += 2
			case 'n':
				result = append(result, '\n')
				i += 2
			case 'r':
				result = append(result, '\r')
				i += 2
			case 't':
				result = append(result, '\t')
				i += 2
			case 'u':
				// Unicode escape: \uXXXX
				if i+5 < len(s) {
					hex := s[i+2 : i+6]
					if val, err := strconv.ParseInt(hex, 16, 32); err == nil {
						// For simplicity, just append as UTF-8
						result = append(result, byte(val))
						i += 6
						continue
					}
				}
				// Invalid unicode escape, keep as-is
				result = append(result, '\\')
				i++
			default:
				// Unknown escape, keep backslash
				result = append(result, '\\')
				i++
			}
		} else {
			result = append(result, s[i])
			i++
		}
	}

	return string(result)
}
