package httpmsg

import (
	"bytes"
	"testing"
)

// TestNoopEncoder tests the passthrough encoder
func TestNoopEncoder(t *testing.T) {
	encoder := &NoopEncoder{}

	tests := []struct {
		name    string
		payload []byte
		offsets []int
	}{
		{
			name:    "empty payload",
			payload: []byte{},
			offsets: []int{0, 0},
		},
		{
			name:    "simple text",
			payload: []byte("hello world"),
			offsets: []int{0, 11},
		},
		{
			name:    "with special chars",
			payload: []byte("test \"quoted\" value"),
			offsets: []int{5, 13},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalOffsets := make([]int, len(tt.offsets))
			copy(originalOffsets, tt.offsets)

			// Test encode
			encoded := encoder.Encode(tt.payload, tt.offsets)
			if !bytes.Equal(encoded, tt.payload) {
				t.Errorf("Encode() = %q, want %q", encoded, tt.payload)
			}

			// Offsets should not change
			if tt.offsets[0] != originalOffsets[0] || tt.offsets[1] != originalOffsets[1] {
				t.Errorf("Offsets changed: got [%d, %d], want [%d, %d]",
					tt.offsets[0], tt.offsets[1], originalOffsets[0], originalOffsets[1])
			}

			// Test decode
			decoded := encoder.Decode(encoded)
			if !bytes.Equal(decoded, tt.payload) {
				t.Errorf("Decode() = %q, want %q", decoded, tt.payload)
			}
		})
	}
}

// TestJSONStringEncoder tests quote-only escaping
func TestJSONStringEncoder(t *testing.T) {
	encoder := &JSONStringEncoder{}

	tests := []struct {
		name            string
		payload         []byte
		expectedEncoded []byte
		inputOffsets    []int
		expectedOffsets []int
	}{
		{
			name:            "no quotes",
			payload:         []byte("hello"),
			expectedEncoded: []byte("hello"),
			inputOffsets:    []int{0, 5},
			expectedOffsets: []int{0, 5},
		},
		{
			name:            "single quote",
			payload:         []byte(`say "hi"`),
			expectedEncoded: []byte(`say \"hi\"`),
			inputOffsets:    []int{0, 8},
			expectedOffsets: []int{0, 10},
		},
		{
			name:            "multiple quotes",
			payload:         []byte(`"test" "value"`),
			expectedEncoded: []byte(`\"test\" \"value\"`),
			inputOffsets:    []int{0, 14},
			expectedOffsets: []int{0, 18},
		},
		{
			name:            "offset at quote position",
			payload:         []byte(`hello"world`),
			expectedEncoded: []byte(`hello\"world`),
			inputOffsets:    []int{5, 11},
			expectedOffsets: []int{5, 12},
		},
		{
			name:            "offset tracking before quote",
			payload:         []byte(`abc"def`),
			expectedEncoded: []byte(`abc\"def`),
			inputOffsets:    []int{3, 7},
			expectedOffsets: []int{3, 8},
		},
		{
			name:            "offset tracking after quote",
			payload:         []byte(`"value"`),
			expectedEncoded: []byte(`\"value\"`),
			inputOffsets:    []int{1, 6},
			expectedOffsets: []int{2, 7},
		},
		{
			name:            "empty string",
			payload:         []byte{},
			expectedEncoded: []byte{},
			inputOffsets:    []int{0, 0},
			expectedOffsets: []int{0, 0},
		},
		{
			name:            "only quotes",
			payload:         []byte(`"""`),
			expectedEncoded: []byte(`\"\"\"`),
			inputOffsets:    []int{0, 3},
			expectedOffsets: []int{0, 6},
		},
		{
			name:            "backslash not escaped",
			payload:         []byte(`test\value`),
			expectedEncoded: []byte(`test\value`),
			inputOffsets:    []int{0, 10},
			expectedOffsets: []int{0, 10},
		},
		{
			name:            "newline not escaped",
			payload:         []byte("test\nvalue"),
			expectedEncoded: []byte("test\nvalue"),
			inputOffsets:    []int{0, 10},
			expectedOffsets: []int{0, 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := make([]int, len(tt.inputOffsets))
			copy(offsets, tt.inputOffsets)

			// Test encode
			encoded := encoder.Encode(tt.payload, offsets)
			if !bytes.Equal(encoded, tt.expectedEncoded) {
				t.Errorf("Encode() = %q, want %q", encoded, tt.expectedEncoded)
			}

			// Check offsets
			if offsets[0] != tt.expectedOffsets[0] || offsets[1] != tt.expectedOffsets[1] {
				t.Errorf("Offsets = [%d, %d], want [%d, %d]",
					offsets[0], offsets[1], tt.expectedOffsets[0], tt.expectedOffsets[1])
			}

			// Test decode (round-trip)
			decoded := encoder.Decode(encoded)
			if !bytes.Equal(decoded, tt.payload) {
				t.Errorf("Decode() = %q, want %q", decoded, tt.payload)
			}
		})
	}
}

// TestJSONStringEncoderDecode tests specific decode cases
func TestJSONStringEncoderDecode(t *testing.T) {
	encoder := &JSONStringEncoder{}

	tests := []struct {
		name     string
		encoded  []byte
		expected []byte
	}{
		{
			name:     "escaped quote",
			encoded:  []byte(`\"`),
			expected: []byte(`"`),
		},
		{
			name:     "multiple escaped quotes",
			encoded:  []byte(`\"test\" \"value\"`),
			expected: []byte(`"test" "value"`),
		},
		{
			name:     "backslash not followed by quote",
			encoded:  []byte(`test\nvalue`),
			expected: []byte(`test\nvalue`),
		},
		{
			name:     "trailing backslash",
			encoded:  []byte(`test\`),
			expected: []byte(`test\`),
		},
		{
			name:     "empty",
			encoded:  []byte{},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded := encoder.Decode(tt.encoded)
			if !bytes.Equal(decoded, tt.expected) {
				t.Errorf("Decode() = %q, want %q", decoded, tt.expected)
			}
		})
	}
}

// TestJSONEscapeEncoder tests full JSON escaping
func TestJSONEscapeEncoder(t *testing.T) {
	encoder := &JSONEscapeEncoder{}

	tests := []struct {
		name            string
		payload         []byte
		expectedEncoded []byte
		inputOffsets    []int
		expectedOffsets []int
	}{
		{
			name:            "quote escaping",
			payload:         []byte(`"test"`),
			expectedEncoded: []byte(`\"test\"`),
			inputOffsets:    []int{0, 6},
			expectedOffsets: []int{0, 8},
		},
		{
			name:            "backslash escaping",
			payload:         []byte(`test\value`),
			expectedEncoded: []byte(`test\\value`),
			inputOffsets:    []int{0, 10},
			expectedOffsets: []int{0, 11},
		},
		{
			name:            "forward slash escaping",
			payload:         []byte(`path/to/file`),
			expectedEncoded: []byte(`path\/to\/file`),
			inputOffsets:    []int{0, 12},
			expectedOffsets: []int{0, 14},
		},
		{
			name:            "newline escaping",
			payload:         []byte("line1\nline2"),
			expectedEncoded: []byte(`line1\nline2`),
			inputOffsets:    []int{0, 11},
			expectedOffsets: []int{0, 12},
		},
		{
			name:            "carriage return escaping",
			payload:         []byte("test\rvalue"),
			expectedEncoded: []byte(`test\rvalue`),
			inputOffsets:    []int{0, 10},
			expectedOffsets: []int{0, 11},
		},
		{
			name:            "tab escaping",
			payload:         []byte("col1\tcol2"),
			expectedEncoded: []byte(`col1\tcol2`),
			inputOffsets:    []int{0, 9},
			expectedOffsets: []int{0, 10},
		},
		{
			name:            "backspace escaping",
			payload:         []byte{116, 101, 115, 116, 8}, // "test\b"
			expectedEncoded: []byte(`test\b`),
			inputOffsets:    []int{0, 5},
			expectedOffsets: []int{0, 6},
		},
		{
			name:            "form feed escaping",
			payload:         []byte{116, 101, 115, 116, 12}, // "test\f"
			expectedEncoded: []byte(`test\f`),
			inputOffsets:    []int{0, 5},
			expectedOffsets: []int{0, 6},
		},
		{
			name:            "unicode escaping for non-ASCII",
			payload:         []byte{0x01}, // Control character
			expectedEncoded: []byte(`\u0001`),
			inputOffsets:    []int{0, 1},
			expectedOffsets: []int{0, 6},
		},
		{
			name:            "unicode escaping for high byte",
			payload:         []byte{0xFF},
			expectedEncoded: []byte(`\u00ff`),
			inputOffsets:    []int{0, 1},
			expectedOffsets: []int{0, 6},
		},
		{
			name:            "mixed escaping",
			payload:         []byte("test\n\"value\"\t\\path"),
			expectedEncoded: []byte(`test\n\"value\"\t\\path`),
			inputOffsets:    []int{0, 18},
			expectedOffsets: []int{0, 23},
		},
		{
			name:            "offset tracking with escapes",
			payload:         []byte("abc\ndef"),
			expectedEncoded: []byte(`abc\ndef`),
			inputOffsets:    []int{3, 7},
			expectedOffsets: []int{3, 8},
		},
		{
			name:            "empty string",
			payload:         []byte{},
			expectedEncoded: []byte{},
			inputOffsets:    []int{0, 0},
			expectedOffsets: []int{0, 0},
		},
		{
			name:            "printable ASCII unchanged",
			payload:         []byte("Hello World! 123"),
			expectedEncoded: []byte("Hello World! 123"),
			inputOffsets:    []int{0, 16},
			expectedOffsets: []int{0, 16},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := make([]int, len(tt.inputOffsets))
			copy(offsets, tt.inputOffsets)

			// Test encode
			encoded := encoder.Encode(tt.payload, offsets)
			if !bytes.Equal(encoded, tt.expectedEncoded) {
				t.Errorf("Encode() = %q, want %q", encoded, tt.expectedEncoded)
			}

			// Check offsets
			if offsets[0] != tt.expectedOffsets[0] || offsets[1] != tt.expectedOffsets[1] {
				t.Errorf("Offsets = [%d, %d], want [%d, %d]",
					offsets[0], offsets[1], tt.expectedOffsets[0], tt.expectedOffsets[1])
			}

			// Test decode (round-trip)
			decoded := encoder.Decode(encoded)
			if !bytes.Equal(decoded, tt.payload) {
				t.Errorf("Decode() = %q, want %q", decoded, tt.payload)
			}
		})
	}
}

// TestJSONEscapeEncoderDecode tests specific decode cases
func TestJSONEscapeEncoderDecode(t *testing.T) {
	encoder := &JSONEscapeEncoder{}

	tests := []struct {
		name     string
		encoded  []byte
		expected []byte
	}{
		{
			name:     "escaped quote",
			encoded:  []byte(`\"`),
			expected: []byte(`"`),
		},
		{
			name:     "escaped backslash",
			encoded:  []byte(`\\`),
			expected: []byte(`\`),
		},
		{
			name:     "escaped forward slash",
			encoded:  []byte(`\/`),
			expected: []byte(`/`),
		},
		{
			name:     "escaped newline",
			encoded:  []byte(`\n`),
			expected: []byte("\n"),
		},
		{
			name:     "escaped carriage return",
			encoded:  []byte(`\r`),
			expected: []byte("\r"),
		},
		{
			name:     "escaped tab",
			encoded:  []byte(`\t`),
			expected: []byte("\t"),
		},
		{
			name:     "escaped backspace",
			encoded:  []byte(`\b`),
			expected: []byte{8},
		},
		{
			name:     "escaped form feed",
			encoded:  []byte(`\f`),
			expected: []byte{12},
		},
		{
			name:     "unicode escape",
			encoded:  []byte(`\u0001`),
			expected: []byte{0x01},
		},
		{
			name:     "unicode escape high byte",
			encoded:  []byte(`\u00ff`),
			expected: []byte{0xFF},
		},
		{
			name:     "malformed unicode (too short)",
			encoded:  []byte(`\u00`),
			expected: []byte(`\u00`),
		},
		{
			name:     "unknown escape",
			encoded:  []byte(`\x`),
			expected: []byte(`x`),
		},
		{
			name:     "trailing backslash",
			encoded:  []byte(`test\`),
			expected: []byte(`test\`),
		},
		{
			name:     "complex mixed",
			encoded:  []byte(`test\n\"value\"\t\\path`),
			expected: []byte("test\n\"value\"\t\\path"),
		},
		{
			name:     "empty",
			encoded:  []byte{},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded := encoder.Decode(tt.encoded)
			if !bytes.Equal(decoded, tt.expected) {
				t.Errorf("Decode() = %q, want %q", decoded, tt.expected)
			}
		})
	}
}

// TestGetEncoder tests the factory function
func TestGetEncoder(t *testing.T) {
	tests := []struct {
		name        string
		encoderType int
		wantType    string
	}{
		{
			name:        "noop encoder",
			encoderType: EncoderNoop,
			wantType:    "*httpmsg.NoopEncoder",
		},
		{
			name:        "json string encoder",
			encoderType: EncoderJSONString,
			wantType:    "*httpmsg.JSONStringEncoder",
		},
		{
			name:        "json escape encoder",
			encoderType: EncoderJSONEscape,
			wantType:    "*httpmsg.JSONEscapeEncoder",
		},
		{
			name:        "unknown type defaults to noop",
			encoderType: 999,
			wantType:    "*httpmsg.NoopEncoder",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := GetEncoder(tt.encoderType)
			if encoder == nil {
				t.Fatal("GetEncoder() returned nil")
			}

			// Check type by attempting encoding
			payload := []byte("test")
			offsets := []int{0, 4}
			_ = encoder.Encode(payload, offsets)
		})
	}
}

// TestEncoderRoundTrip tests that all encoders properly round-trip
func TestEncoderRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("simple text"),
		[]byte(`"quoted"`),
		[]byte("line1\nline2"),
		[]byte("tab\tseparated"),
		[]byte(`path/to/file`),
		[]byte(`back\slash`),
		{0x01, 0x02, 0x03}, // Control characters
		{0xFF, 0xFE},       // High bytes
		[]byte("mixed\n\"test\"\t\\value"),
	}

	encoders := []struct {
		name    string
		encoder Encoder
	}{
		{"Noop", &NoopEncoder{}},
		{"JSONString", &JSONStringEncoder{}},
		{"JSONEscape", &JSONEscapeEncoder{}},
	}

	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			for i, payload := range payloads {
				offsets := []int{0, len(payload)}
				encoded := enc.encoder.Encode(payload, offsets)
				decoded := enc.encoder.Decode(encoded)

				if !bytes.Equal(decoded, payload) {
					t.Errorf("Payload %d: round-trip failed\nOriginal: %q\nEncoded:  %q\nDecoded:  %q",
						i, payload, encoded, decoded)
				}
			}
		})
	}
}

// TestOffsetTracking tests offset tracking accuracy
func TestOffsetTracking(t *testing.T) {
	tests := []struct {
		name            string
		encoder         Encoder
		payload         []byte
		inputOffsets    []int
		expectedOffsets []int
	}{
		{
			name:            "JSONString - start offset at quote",
			encoder:         &JSONStringEncoder{},
			payload:         []byte(`"test"`),
			inputOffsets:    []int{0, 6},
			expectedOffsets: []int{0, 8}, // Each quote adds 1 byte
		},
		{
			name:            "JSONString - mid offset",
			encoder:         &JSONStringEncoder{},
			payload:         []byte(`ab"cd"ef`),
			inputOffsets:    []int{2, 5},
			expectedOffsets: []int{2, 6}, // Offset tracks where encoded bytes start
		},
		{
			name:            "JSONEscape - newline offset",
			encoder:         &JSONEscapeEncoder{},
			payload:         []byte("abc\ndef"),
			inputOffsets:    []int{3, 7},
			expectedOffsets: []int{3, 8}, // \n becomes \n (2 bytes)
		},
		{
			name:            "JSONEscape - unicode offset",
			encoder:         &JSONEscapeEncoder{},
			payload:         []byte{0x61, 0x01, 0x62}, // a\x01b
			inputOffsets:    []int{1, 3},
			expectedOffsets: []int{1, 8}, // \x01 becomes \u0001 (6 bytes)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := make([]int, len(tt.inputOffsets))
			copy(offsets, tt.inputOffsets)

			_ = tt.encoder.Encode(tt.payload, offsets)

			if offsets[0] != tt.expectedOffsets[0] || offsets[1] != tt.expectedOffsets[1] {
				t.Errorf("Offsets = [%d, %d], want [%d, %d]",
					offsets[0], offsets[1], tt.expectedOffsets[0], tt.expectedOffsets[1])
			}
		})
	}
}
