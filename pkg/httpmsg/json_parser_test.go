package httpmsg

import (
	"fmt"
	"strings"
	"testing"
)

// TestJSONParser_EscapedStrings tests the CRITICAL functionality that was broken in the old parser.
// The old parser would search for decoded values in raw JSON, causing offset mismatches and panics.
// The new parser handles escapes correctly by tracking position during character-by-character parsing.
func TestJSONParser_EscapedStrings(t *testing.T) {
	tests := []struct {
		name          string
		json          string
		expectedCount int
		expectations  map[string]struct {
			value    string
			metadata string
		}
	}{
		{
			name:          "escaped quotes in value",
			json:          `{"message":"Hello \"World\""}`,
			expectedCount: 1,
			expectations: map[string]struct {
				value    string
				metadata string
			}{
				"message": {
					value:    `Hello "World"`, // Decoded value
					metadata: "message",
				},
			},
		},
		{
			name:          "escaped backslashes",
			json:          `{"path":"C:\\Users\\test\\file.txt"}`,
			expectedCount: 1,
			expectations: map[string]struct {
				value    string
				metadata string
			}{
				"path": {
					value:    `C:\Users\test\file.txt`, // Decoded value
					metadata: "path",
				},
			},
		},
		{
			name:          "mixed escape sequences",
			json:          `{"text":"Line1\nLine2\tTabbed\rReturn"}`,
			expectedCount: 1,
			expectations: map[string]struct {
				value    string
				metadata string
			}{
				"text": {
					value:    "Line1\nLine2\tTabbed\rReturn", // Decoded
					metadata: "text",
				},
			},
		},
		{
			name:          "unicode escapes",
			json:          `{"unicode":"test\u0041value\u0042end"}`,
			expectedCount: 1,
			expectations: map[string]struct {
				value    string
				metadata string
			}{
				"unicode": {
					value:    "testAvalueBend", // \u0041 = A, \u0042 = B
					metadata: "unicode",
				},
			},
		},
		{
			name:          "complex nested with escapes",
			json:          `{"user":{"name":"John \"The Boss\" Smith","title":"CEO\\CFO"}}`,
			expectedCount: 2,
			expectations: map[string]struct {
				value    string
				metadata string
			}{
				"name": {
					value:    `John "The Boss" Smith`,
					metadata: "user.name",
				},
				"title": {
					value:    `CEO\CFO`,
					metadata: "user.title",
				},
			},
		},
		{
			name:          "multiple escape types in array",
			json:          `{"items":["text\"quote","path\\slash","new\nline"]}`,
			expectedCount: 3,
			expectations: map[string]struct {
				value    string
				metadata string
			}{
				// For arrays, all elements share the same name
				// We just verify they all have the correct metadata path
				// Values can be any of the array elements
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			if len(params) != tt.expectedCount {
				t.Errorf("Expected %d parameters, got %d", tt.expectedCount, len(params))
			}

			// Verify parameters against expectations
			// For array test cases with no expectations, just verify count
			if len(tt.expectations) > 0 {
				for _, param := range params {
					if expected, ok := tt.expectations[param.Name()]; ok {
						if param.Value() != expected.value {
							t.Errorf("Parameter %s: expected value %q, got %q",
								param.Name(), expected.value, param.Value())
						}
						if param.Metadata() != expected.metadata {
							t.Errorf("Parameter %s: expected metadata %q, got %q",
								param.Name(), expected.metadata, param.Metadata())
						}
					}
				}
			} else {
				// For array cases, just verify all params have correct metadata path
				for _, param := range params {
					if param.Metadata() != "items" {
						t.Errorf("Expected metadata 'items', got %q", param.Metadata())
					}
				}
			}
		})
	}
}

// TestJSONParser_OffsetAccuracy tests that byte offsets are accurate.
// This is CRITICAL - incorrect offsets caused the "Invalid offsets" panic.
func TestJSONParser_OffsetAccuracy(t *testing.T) {
	tests := []struct {
		name       string
		json       string
		validateFn func(*testing.T, []byte, []*Param)
	}{
		{
			name: "simple values have correct offsets",
			json: `{"key":"value"}`,
			validateFn: func(t *testing.T, request []byte, params []*Param) {
				if len(params) != 1 {
					t.Fatalf("Expected 1 parameter, got %d", len(params))
				}
				p := params[0]

				// Extract value using offsets
				bodyOffset := findBodyOffset(request)
				extractedValue := string(request[p.ValueStart():p.ValueEnd()])

				// For strings, offsets should point to content WITHOUT quotes
				// In raw JSON: {"key":"value"}
				//                     ^^^^^  <- offsets should point here (excluding quotes)
				if extractedValue != "value" {
					t.Errorf("Extracted value %q doesn't match expected %q", extractedValue, "value")
				}

				// Verify offsets are within bounds
				if p.ValueStart() < bodyOffset || p.ValueEnd() > len(request) {
					t.Errorf("Offsets out of bounds: [%d:%d], request length: %d",
						p.ValueStart(), p.ValueEnd(), len(request))
				}

				if p.ValueStart() >= p.ValueEnd() {
					t.Errorf("Invalid offsets: start %d >= end %d", p.ValueStart(), p.ValueEnd())
				}
			},
		},
		{
			name: "escaped strings point to raw content with escapes",
			json: `{"path":"C:\\Users\\test"}`,
			validateFn: func(t *testing.T, request []byte, params []*Param) {
				if len(params) != 1 {
					t.Fatalf("Expected 1 parameter, got %d", len(params))
				}
				p := params[0]

				// Extract RAW value (with escapes intact)
				extractedRaw := string(request[p.ValueStart():p.ValueEnd()])

				// Should point to RAW content: C:\\Users\\test (with backslashes)
				if extractedRaw != `C:\\Users\\test` {
					t.Errorf("Raw value %q should contain escape sequences", extractedRaw)
				}

				// But Parameter.Value should be decoded
				if p.Value() != `C:\Users\test` {
					t.Errorf("Decoded value %q should have escapes processed", p.Value())
				}
			},
		},
		{
			name: "nested objects maintain accurate offsets",
			json: `{"outer":{"inner":"value"}}`,
			validateFn: func(t *testing.T, request []byte, params []*Param) {
				if len(params) != 1 {
					t.Fatalf("Expected 1 parameter, got %d", len(params))
				}
				p := params[0]

				// Verify offset validity
				if p.ValueStart() < 0 || p.ValueEnd() < 0 {
					t.Errorf("Negative offsets detected: [%d:%d]", p.ValueStart(), p.ValueEnd())
				}

				if p.ValueStart() >= p.ValueEnd() {
					t.Errorf("Invalid offset range: start %d >= end %d", p.ValueStart(), p.ValueEnd())
				}

				// Verify offset within request bounds
				if p.ValueEnd() > len(request) {
					t.Errorf("ValueEnd %d exceeds request length %d", p.ValueEnd(), len(request))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			tt.validateFn(t, request, params)
		})
	}
}

// TestJSONParser_NestedStructures tests complex nested JSON parsing.
// Verifies that path construction works correctly for deeply nested data.
func TestJSONParser_NestedStructures(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected map[string]string // name -> metadata (path)
	}{
		{
			name: "simple nesting",
			json: `{"user":{"name":"alice","email":"alice@example.com"}}`,
			expected: map[string]string{
				"name":  "user.name",
				"email": "user.email",
			},
		},
		{
			name: "deep nesting",
			json: `{"a":{"b":{"c":{"d":"value"}}}}`,
			expected: map[string]string{
				"d": "a.b.c.d",
			},
		},
		{
			name: "array elements share same path",
			json: `{"items":[{"id":1},{"id":2},{"id":3}]}`,
			expected: map[string]string{
				"id": "items.id", // All array elements use same path
			},
		},
		{
			name: "mixed nesting with arrays and objects",
			json: `{"data":{"users":[{"name":"alice","role":"admin"}],"count":1}}`,
			expected: map[string]string{
				"name":  "data.users.name",
				"role":  "data.users.role",
				"count": "data.count",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			// Verify each parameter has correct metadata path
			foundPaths := make(map[string]bool)
			for _, param := range params {
				if expectedPath, ok := tt.expected[param.Name()]; ok {
					if param.Metadata() != expectedPath {
						t.Errorf("Parameter %s: expected path %q, got %q",
							param.Name(), expectedPath, param.Metadata())
					}
					foundPaths[param.Name()] = true
				}
			}

			// Verify all expected parameters were found
			for name := range tt.expected {
				if !foundPaths[name] {
					t.Errorf("Expected parameter %q not found", name)
				}
			}
		})
	}
}

// TestJSONParser_ValueTypes tests parsing of different JSON value types.
func TestJSONParser_ValueTypes(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected map[string]string // name -> expected value
	}{
		{
			name: "string values",
			json: `{"text":"hello world"}`,
			expected: map[string]string{
				"text": "hello world",
			},
		},
		{
			name: "integer values",
			json: `{"count":42,"negative":-10,"zero":0}`,
			expected: map[string]string{
				"count":    "42",
				"negative": "-10",
				"zero":     "0",
			},
		},
		{
			name: "float values",
			json: `{"pi":3.14,"scientific":1.23e10}`,
			expected: map[string]string{
				"pi":         "3.14",
				"scientific": "1.23e10",
			},
		},
		{
			name: "boolean values",
			json: `{"active":true,"deleted":false}`,
			expected: map[string]string{
				"active":  "true",
				"deleted": "false",
			},
		},
		{
			name: "null values",
			json: `{"value":null}`,
			expected: map[string]string{
				"value": "null",
			},
		},
		{
			name: "mixed types",
			json: `{"str":"text","num":123,"bool":true,"nil":null}`,
			expected: map[string]string{
				"str":  "text",
				"num":  "123",
				"bool": "true",
				"nil":  "null",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			paramMap := make(map[string]*Param)
			for _, p := range params {
				paramMap[p.Name()] = p
			}

			for name, expectedValue := range tt.expected {
				param, ok := paramMap[name]
				if !ok {
					t.Errorf("Parameter %q not found", name)
					continue
				}
				if param.Value() != expectedValue {
					t.Errorf("Parameter %s: expected value %q, got %q",
						name, expectedValue, param.Value())
				}
			}
		})
	}
}

// TestJSONParser_Arrays tests array parsing behavior.
// Burp's behavior: array elements don't get indexed paths - all share the parent key name.
func TestJSONParser_Arrays(t *testing.T) {
	tests := []struct {
		name          string
		json          string
		expectedCount int
		expectedName  string
		expectedPath  string
	}{
		{
			name:          "simple array",
			json:          `{"items":[1,2,3]}`,
			expectedCount: 3,
			expectedName:  "items",
			expectedPath:  "items",
		},
		{
			name:          "array of strings",
			json:          `{"tags":["tag1","tag2"]}`,
			expectedCount: 2,
			expectedName:  "tags",
			expectedPath:  "tags",
		},
		{
			name:          "array of objects",
			json:          `{"users":[{"id":1},{"id":2}]}`,
			expectedCount: 2, // 2 id parameters
			expectedName:  "id",
			expectedPath:  "users.id",
		},
		{
			name:          "nested arrays",
			json:          `{"matrix":[[1,2],[3,4]]}`,
			expectedCount: 4, // All leaf values
			expectedName:  "matrix",
			expectedPath:  "matrix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			if len(params) != tt.expectedCount {
				t.Errorf("Expected %d parameters, got %d", tt.expectedCount, len(params))
			}

			// Verify all parameters share the same name and path
			for _, param := range params {
				if param.Name() != tt.expectedName {
					t.Errorf("Expected name %q, got %q", tt.expectedName, param.Name())
				}
				if param.Metadata() != tt.expectedPath {
					t.Errorf("Expected path %q, got %q", tt.expectedPath, param.Metadata())
				}
			}
		})
	}
}

// TestJSONParser_EmptyStructures tests handling of empty objects and arrays.
func TestJSONParser_EmptyStructures(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected int
	}{
		{"empty object", `{}`, 0},
		{"empty array", `[]`, 0},
		{"object with empty nested object", `{"data":{}}`, 0},
		{"object with empty array", `{"items":[]}`, 0},
		{"empty nested in valid structure", `{"a":1,"b":{},"c":[]}`, 1}, // Only "a" creates param
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			if len(params) != tt.expected {
				t.Errorf("Expected %d parameters, got %d", tt.expected, len(params))
			}
		})
	}
}

// TestJSONParser_LenientParsing tests that parser handles malformed JSON gracefully.
// Burp's parser is lenient - it extracts what it can without strict validation.
func TestJSONParser_LenientParsing(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		expectError bool
		minParams   int // Minimum parameters that should be extracted
	}{
		{
			name:        "missing closing brace",
			json:        `{"user":"john"`,
			expectError: false, // Burp is lenient
			minParams:   0,     // May or may not extract anything
		},
		{
			name:        "trailing comma",
			json:        `{"user":"john",}`,
			expectError: false,
			minParams:   0,
		},
		{
			name:        "unquoted keys (invalid but parseable)",
			json:        `{user:"john"}`,
			expectError: false,
			minParams:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if len(params) < tt.minParams {
				t.Errorf("Expected at least %d parameters, got %d", tt.minParams, len(params))
			}
		})
	}
}

// TestJSONParser_RealWorldScenarios tests complex real-world JSON structures.
func TestJSONParser_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "API response with metadata",
			json: `{
				"status": "success",
				"data": {
					"user": {
						"id": 123,
						"name": "John \"The Boss\" Smith",
						"email": "john@example.com",
						"settings": {
							"theme": "dark",
							"notifications": true
						}
					}
				},
				"timestamp": "2024-01-01T00:00:00Z"
			}`,
		},
		{
			name: "configuration with paths",
			json: `{
				"config": {
					"database": {
						"host": "localhost",
						"port": 5432,
						"path": "C:\\Users\\admin\\database"
					},
					"features": ["auth", "api", "dashboard"]
				}
			}`,
		},
		{
			name: "deeply nested with arrays",
			json: `{
				"company": {
					"departments": [
						{
							"name": "Engineering",
							"employees": [
								{"id": 1, "name": "Alice"},
								{"id": 2, "name": "Bob"}
							]
						}
					]
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compress JSON (remove newlines/spaces)
			compactJSON := strings.ReplaceAll(tt.json, "\n", "")
			compactJSON = strings.ReplaceAll(compactJSON, "\t", "")

			request := buildJSONRequest(compactJSON)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			// Verify basic sanity
			if len(params) == 0 {
				t.Error("Expected to extract some parameters from real-world JSON")
			}

			// Verify all parameters have valid offsets
			for i, param := range params {
				if param.ValueStart() < 0 || param.ValueEnd() < 0 {
					t.Errorf("Parameter %d (%s) has invalid offsets: [%d:%d]",
						i, param.Name(), param.ValueStart(), param.ValueEnd())
				}
				if param.ValueStart() >= param.ValueEnd() {
					t.Errorf("Parameter %d (%s) has invalid offset range: start=%d >= end=%d",
						i, param.Name(), param.ValueStart(), param.ValueEnd())
				}
				if param.Type() != ParamJSON {
					t.Errorf("Parameter %d (%s) has wrong type: expected ParamJSON, got %d",
						i, param.Name(), param.Type())
				}
			}
		})
	}
}

// TestJSONParser_ParamType verifies all parameters have correct type.
func TestJSONParser_ParamType(t *testing.T) {
	json := `{"user":"alice","age":30,"nested":{"value":"test"}}`
	request := buildJSONRequest(json)
	params, err := ParseJSONBody(request, findBodyOffset(request))

	if err != nil {
		t.Fatalf("ParseJSONBody failed: %v", err)
	}

	for i, param := range params {
		if param.Type() != ParamJSON {
			t.Errorf("Parameter %d (%s) has incorrect type: expected ParamJSON (7), got %d",
				i, param.Name(), param.Type())
		}
	}
}

// TestJSONParser_EdgeCases tests various edge cases.
func TestJSONParser_EdgeCases(t *testing.T) {
	t.Run("empty body", func(t *testing.T) {
		request := []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n")
		params, err := ParseJSONBody(request, findBodyOffset(request))

		// Should return error for empty body
		if err == nil {
			t.Error("Expected error for empty body")
		}
		if params != nil {
			t.Errorf("Expected nil params for error case, got %d params", len(params))
		}
	})

	t.Run("bodyOffset at end", func(t *testing.T) {
		request := []byte("POST /api HTTP/1.1\r\n\r\n")
		_, err := ParseJSONBody(request, len(request))

		if err == nil {
			t.Error("Expected error when bodyOffset >= request length")
		}
	})

	t.Run("very long value", func(t *testing.T) {
		longValue := strings.Repeat("a", 10000)
		json := fmt.Sprintf(`{"long":"%s"}`, longValue)
		request := buildJSONRequest(json)
		params, err := ParseJSONBody(request, findBodyOffset(request))

		if err != nil {
			t.Fatalf("ParseJSONBody failed: %v", err)
		}
		if len(params) != 1 {
			t.Fatalf("Expected 1 parameter, got %d", len(params))
		}
		if params[0].Value() != longValue {
			t.Error("Long value not parsed correctly")
		}
	})
}

// Benchmark tests to ensure parser performance is acceptable.
func BenchmarkJSONParser_Simple(b *testing.B) {
	json := `{"user":"alice","age":30,"active":true}`
	request := buildJSONRequest(json)
	bodyOffset := findBodyOffset(request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseJSONBody(request, bodyOffset)
	}
}

func BenchmarkJSONParser_Nested(b *testing.B) {
	json := `{"data":{"user":{"profile":{"name":"alice","email":"alice@example.com"}}}}`
	request := buildJSONRequest(json)
	bodyOffset := findBodyOffset(request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseJSONBody(request, bodyOffset)
	}
}

func BenchmarkJSONParser_Array(b *testing.B) {
	json := `{"items":[1,2,3,4,5,6,7,8,9,10]}`
	request := buildJSONRequest(json)
	bodyOffset := findBodyOffset(request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseJSONBody(request, bodyOffset)
	}
}

func BenchmarkJSONParser_Escaped(b *testing.B) {
	json := `{"path":"C:\\Users\\test\\file.txt","message":"Hello \"World\""}`
	request := buildJSONRequest(json)
	bodyOffset := findBodyOffset(request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseJSONBody(request, bodyOffset)
	}
}

// Helper functions

func buildJSONRequest(jsonBody string) []byte {
	return []byte(fmt.Sprintf("POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n%s", jsonBody))
}

func findBodyOffset(request []byte) int {
	// Find \r\n\r\n or \n\n
	for i := 0; i < len(request)-3; i++ {
		if request[i] == '\r' && request[i+1] == '\n' &&
			request[i+2] == '\r' && request[i+3] == '\n' {
			return i + 4
		}
		if request[i] == '\n' && request[i+1] == '\n' {
			return i + 2
		}
	}
	return len(request)
}

// TestJSONParser_TypeDetection tests that JSON value types are correctly detected.
func TestJSONParser_TypeDetection(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		paramName    string
		expectedType JSONValueType
	}{
		{"string value", `{"name":"john"}`, "name", JSONTypeString},
		{"string empty", `{"name":""}`, "name", JSONTypeString},
		{"string with escapes", `{"path":"C:\\Users"}`, "path", JSONTypeString},
		{"number integer", `{"age":30}`, "age", JSONTypeNumber},
		{"number zero", `{"count":0}`, "count", JSONTypeNumber},
		{"number negative", `{"temp":-5}`, "temp", JSONTypeNumber},
		{"number float", `{"pi":3.14}`, "pi", JSONTypeNumber},
		{"number scientific", `{"val":1.5e10}`, "val", JSONTypeNumber},
		{"number negative scientific", `{"val":-3.14e-5}`, "val", JSONTypeNumber},
		{"bool true", `{"active":true}`, "active", JSONTypeBool},
		{"bool false", `{"deleted":false}`, "deleted", JSONTypeBool},
		{"null value", `{"data":null}`, "data", JSONTypeNull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildJSONRequest(tt.json)
			params, err := ParseJSONBody(request, findBodyOffset(request))

			if err != nil {
				t.Fatalf("ParseJSONBody failed: %v", err)
			}

			// Find the parameter by name
			var found *Param
			for _, p := range params {
				if p.Name() == tt.paramName {
					found = p
					break
				}
			}

			if found == nil {
				t.Fatalf("Parameter %q not found", tt.paramName)
			}

			if found.JSONType() != tt.expectedType {
				t.Errorf("JSONValueType = %d, want %d", found.JSONType(), tt.expectedType)
			}
		})
	}
}

// TestJSONParser_TypeDetection_MixedTypes tests multiple types in one JSON object.
func TestJSONParser_TypeDetection_MixedTypes(t *testing.T) {
	json := `{"str":"text","num":123,"bool":true,"nil":null,"float":3.14}`
	request := buildJSONRequest(json)
	params, err := ParseJSONBody(request, findBodyOffset(request))

	if err != nil {
		t.Fatalf("ParseJSONBody failed: %v", err)
	}

	expected := map[string]JSONValueType{
		"str":   JSONTypeString,
		"num":   JSONTypeNumber,
		"bool":  JSONTypeBool,
		"nil":   JSONTypeNull,
		"float": JSONTypeNumber,
	}

	for _, p := range params {
		if expectedType, ok := expected[p.Name()]; ok {
			if p.JSONType() != expectedType {
				t.Errorf("Parameter %s: JSONValueType = %d, want %d", p.Name(), p.JSONType(), expectedType)
			}
		}
	}
}

// TestJSONParser_TypeDetection_Nested tests type detection in nested objects.
func TestJSONParser_TypeDetection_Nested(t *testing.T) {
	json := `{"user":{"name":"alice","age":30,"active":true}}`
	request := buildJSONRequest(json)
	params, err := ParseJSONBody(request, findBodyOffset(request))

	if err != nil {
		t.Fatalf("ParseJSONBody failed: %v", err)
	}

	expected := map[string]JSONValueType{
		"name":   JSONTypeString,
		"age":    JSONTypeNumber,
		"active": JSONTypeBool,
	}

	for _, p := range params {
		if expectedType, ok := expected[p.Name()]; ok {
			if p.JSONType() != expectedType {
				t.Errorf("Parameter %s: JSONValueType = %d, want %d", p.Name(), p.JSONType(), expectedType)
			}
		}
	}
}

// TestJSONParser_TypeDetection_Arrays tests type detection in arrays.
func TestJSONParser_TypeDetection_Arrays(t *testing.T) {
	json := `{"numbers":[1,2,3],"strings":["a","b"],"mixed":[true,null,42]}`
	request := buildJSONRequest(json)
	params, err := ParseJSONBody(request, findBodyOffset(request))

	if err != nil {
		t.Fatalf("ParseJSONBody failed: %v", err)
	}

	// All "numbers" elements should be JSONTypeNumber
	// All "strings" elements should be JSONTypeString
	// "mixed" has different types
	for _, p := range params {
		switch p.Name() {
		case "numbers":
			if p.JSONType() != JSONTypeNumber {
				t.Errorf("numbers element: JSONValueType = %d, want %d", p.JSONType(), JSONTypeNumber)
			}
		case "strings":
			if p.JSONType() != JSONTypeString {
				t.Errorf("strings element: JSONValueType = %d, want %d", p.JSONType(), JSONTypeString)
			}
		}
	}
}
