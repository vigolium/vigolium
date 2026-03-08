package httpmsg

// JSON Parameter Extractor
// Direct port of Burp Suite's character-by-character JSON parser (bag.java)
//
// BURP SOURCE FILE MAPPING:
//   - bag.java: Main JSON parser with manual character-by-character parsing
//     Location: /reverse/burp_reverse_sourcecode/burp/bag.java
//
// CRITICAL DESIGN DECISION:
//   - Burp does NOT use a JSON library
//   - Burp manually parses character-by-character to track byte offsets
//   - This allows returning offsets to RAW JSON (with escape sequences intact)
//   - Trying to use json.Unmarshal then search for decoded values FAILS
//
// Algorithm (from bag.java):
//  1. Manual state machine parsing (no JSON library)
//  2. Track position index (this.b in Java → pos in Go)
//  3. Parse structure characters: { } [ ] : , "
//  4. Handle escape sequences: when \ found, skip next character
//  5. Return raw byte offsets pointing to content in original JSON
//
// Method Mapping (Burp → Go):
//   bag.java line 14  → ParseJSONBody()           Entry point
//   bag.java line 36  → parseObject()              Parse {key:value,...}
//   bag.java line 90  → parseArray()               Parse [value,value,...]
//   bag.java line 130 → parseValue()               Parse any value type
//   bag.java line 146 → parseQuotedString()        Parse "..." with escape handling
//   bag.java line 182 → parseUnquotedValue()       Parse numbers/bool/null
//   bag.java line 210 → skipWhitespace()           Skip spaces/tabs/newlines

import (
	"fmt"
	"strconv"
)

// jsonParser is the state machine for character-by-character JSON parsing.
// Directly mirrors Burp's bag.java fields and parsing approach.
//
// Field mapping from bag.java:
//   - d (bi9) → data ([]byte) - The raw JSON bytes
//   - b (int) → pos (int) - Current position index (this.b in Java)
//   - a (int) → end (int) - End position (this.a in Java)
//   - c (List<cwa>) → params ([]*Param) - Collected parameters
type jsonParser struct {
	data       []byte   // Raw JSON bytes (bag.java field 'd')
	pos        int      // Current position (bag.java field 'b')
	end        int      // End position (bag.java field 'a')
	baseOffset int      // Offset to adjust for position in full request
	params     []*Param // Collected parameters (bag.java field 'c')
	path       string   // Current JSON path (for metadata)
}

// ParseJSONBody parses application/json body and extracts parameters.
// Ported from: bag.java static method a(bi9, int, int, Supplier<Boolean>) [line 14-16]
//
// Algorithm (from bag.java):
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

	// Create parser (maps to bag.java constructor at line 18-34)
	p := &jsonParser{
		data:       body,
		pos:        0,
		end:        len(body),
		baseOffset: bodyOffset,
		params:     make([]*Param, 0),
		path:       "",
	}

	// Start parsing (maps to bag.java line 27: this.a(new int[]{0, 0}, (byte)0, var4))
	// The initial call with empty int[]{0, 0} means no parent key for root value
	if err := p.parseValue(nil, 0); err != nil {
		return []*Param{}, nil // Burp returns empty list on parse errors
	}

	return p.params, nil
}

// parseValue parses a JSON value at current position.
// Ported from: bag.java method a(int[], byte, Supplier<Boolean>) [lines 130-144]
//
// Algorithm (from bag.java lines 130-144):
//  1. Skip whitespace
//  2. Check first character:
//     - 34 (") → Parse quoted string (call d())
//     - 91 ([) → Parse array (call a(int[], Supplier))
//     - 123 ({) → Parse object (call a(Supplier))
//     - Other → Parse unquoted value (call a(byte, byte))
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
	case '"': // Quoted string value (line 133-134)
		valueOffsets := p.parseQuotedString()
		if valueOffsets != nil && keyOffsets != nil {
			p.createParameterWithType(keyOffsets, valueOffsets, JSONTypeString)
		}
		return nil

	case '[': // Array value (line 135-137)
		p.parseArray(keyOffsets)
		return nil

	case '{': // Object value (line 138-140)
		p.parseObject()
		return nil

	default: // Unquoted value: number, boolean, null (line 141-142)
		valueOffsets, valueType := p.parseUnquotedValueWithType(',', delimiter)
		if valueOffsets != nil && keyOffsets != nil {
			p.createParameterWithType(keyOffsets, valueOffsets, valueType)
		}
		return nil
	}
}

// parseObject parses a JSON object: {key1:value1, key2:value2, ...}
// Ported from: bag.java method a(Supplier<Boolean>) [lines 36-88]
//
// Algorithm (from bag.java lines 36-88):
//  1. Check opening { (line 39)
//  2. Loop while not } (lines 42-84):
//     a. Parse key string with d() (line 54)
//     b. Check for : separator (line 56-58)
//     c. Parse value with a(int[], byte, Supplier) (line 61)
//     d. Create parameter (line 63)
//     e. Check for , or } (lines 67-78)
//  3. Move past } (line 77)
func (p *jsonParser) parseObject() {
	savedPath := p.path

	p.skipWhitespace()
	if p.pos >= p.end || p.data[p.pos] != '{' {
		return
	}

	p.pos++ // Skip {

	for p.pos < p.end {
		p.skipWhitespace()

		// Check for closing } (line 47)
		if p.data[p.pos] == '}' {
			p.pos++
			p.path = savedPath
			return
		}

		// Parse key (line 54 → calls d())
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

		// Check for : separator (lines 56-58)
		if p.pos >= p.end || p.data[p.pos] != ':' {
			p.path = savedPath
			return
		}
		p.pos++ // Skip :

		// Parse value (line 61)
		_ = p.parseValue(keyOffsets, '}')

		// Restore path after value
		p.path = savedPath

		p.skipWhitespace()

		// Check for , or } (lines 67-78)
		if p.pos >= p.end {
			return
		}

		switch p.data[p.pos] {
		case ',': // Continue to next key-value pair (line 68-74)
			p.pos++
			p.skipWhitespace()
			if p.pos < p.end && p.data[p.pos] == '}' {
				p.pos++
				return
			}
		case '}': // End of object (lines 76-78)
			p.pos++
			return
		default:
			return
		}
	}
}

// parseArray parses a JSON array: [value1, value2, ...]
// Ported from: bag.java method a(int[], Supplier<Boolean>) [lines 90-128]
//
// Algorithm (from bag.java lines 90-128):
//  1. Check opening [ (line 93)
//  2. Loop while not ] (lines 96-124):
//     a. Parse value with a(int[], byte, Supplier) (line 101)
//     b. Create parameter using SAME keyOffsets for all elements (line 103)
//     This is Burp's behavior: array elements don't get indexed paths
//     c. Check for , or ] (lines 107-118)
//  3. Move past ] (line 117)
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
		// Parse value (line 101)
		// Note: Burp passes the SAME keyOffsets to all array elements
		// This means all elements share the same parameter name
		_ = p.parseValue(keyOffsets, ']')

		p.skipWhitespace()

		if p.pos >= p.end {
			return
		}

		// Check for , or ] (lines 107-118)
		switch p.data[p.pos] {
		case ',': // Continue to next element (line 108-114)
			p.pos++
			p.skipWhitespace()
			if p.pos < p.end && p.data[p.pos] == ']' {
				p.pos++
				return
			}
		case ']': // End of array (lines 116-118)
			p.pos++
			return
		default:
			return
		}
	}
}

// parseQuotedString parses a quoted JSON string and returns its byte offsets.
// Ported from: bag.java method d() [lines 146-180]
//
// CRITICAL: This handles escape sequences correctly.
// When \ is found, the next character is skipped (line 164-165).
// This allows returning offsets to the RAW content in the original JSON.
//
// Algorithm (from bag.java lines 146-180):
//  1. Skip whitespace
//  2. Check for opening " (line 149)
//  3. Skip " and mark start (lines 152-153)
//  4. Loop until closing " (lines 157-172):
//     - If " found → mark end and break (lines 159-160)
//     - If \ found → skip next character (lines 164-165)
//     - Otherwise → continue (line 167)
//  5. Return [start, end] offsets (line 178)
//
// Returns:
//   - int[]{start, end} pointing to content (excluding quotes)
//   - nil if not a valid quoted string
func (p *jsonParser) parseQuotedString() []int {
	p.skipWhitespace()

	if p.pos >= p.end || p.data[p.pos] != '"' {
		// Not a quoted string, try unquoted (for lenient parsing)
		// bag.java line 150: calls a(byte, byte) if not quoted
		offsets, _ := p.parseUnquotedValueWithType(':', 0)
		return offsets
	}

	p.pos++ // Skip opening " (line 152)
	start := p.pos

	end := -1
	for p.pos < p.end {
		switch p.data[p.pos] {
		case '"': // Found closing " (lines 159-163)
			end = p.pos
			p.pos++ // Move past "
			return []int{start, end}

		case '\\': // Found escape sequence (lines 164-165)
			// CRITICAL: Skip the backslash AND the next character
			// This is how Burp handles \", \\, \n, etc.
			p.pos++ // Skip \
			if p.pos < p.end {
				p.pos++ // Skip escaped character
			}

		default: // Regular character (line 167)
			p.pos++
		}
	}

	// String not properly closed, use end of data (lines 174-176)
	if end == -1 {
		end = p.end
	}

	return []int{start, end}
}

// parseUnquotedValueWithType parses an unquoted JSON value (number, boolean, null)
// and returns both the offsets and the detected JSON value type.
// Ported from: bag.java method a(byte, byte) [lines 182-208]
//
// Algorithm (from bag.java lines 182-208):
//  1. Mark start position (line 183)
//  2. Loop until delimiter or whitespace (lines 188-201):
//     - Check for whitespace (<=32) or delimiters (lines 190-195)
//     - If found → mark end and break
//  3. If no delimiter found, use end of data (lines 203-205)
//  4. Detect value type from raw content
//  5. Return [start, end] and type, or nil if empty (line 207)
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

		// Check for end conditions (lines 190-195):
		// - Whitespace (b <= 32)
		// - Delimiter 1 (b == delim1)
		// - Delimiter 2 (b == delim2)
		if b <= 32 || b == delim1 || b == delim2 {
			end = p.pos
			break
		}

		p.pos++
	}

	// If no terminator found, use end of data (lines 203-205)
	if end == -1 {
		end = p.end
	}

	// Return nil if empty value (line 207)
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

// skipWhitespace skips over whitespace characters.
// Ported from: bag.java method c() [lines 210-228]
//
// Algorithm (from bag.java lines 210-228):
//  1. Loop while position < end (lines 213-223)
//  2. Check if byte is whitespace (b > 32 || b < 0) (line 215)
//  3. If not whitespace → break
//  4. Otherwise → increment position (line 219)
func (p *jsonParser) skipWhitespace() {
	for p.pos < p.end {
		b := p.data[p.pos]
		// Whitespace check: b <= 32 (line 215 inverted)
		if b > 32 {
			break
		}
		p.pos++
	}
}

// createParameterWithType creates a Param from key and value offsets with JSON type info.
// Ported from: bag.java parameter creation at lines 63 and 103
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
