package utils

import (
	"bytes" // Used for DeepEqual on byte slices
	"testing"
)

// TestBytesToString tests the BytesToString function.
func TestBytesToString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "nil byte array",
			input: nil,
			want:  "",
		},
		{
			name:  "empty byte array",
			input: []byte{},
			want:  "",
		},
		{
			name:  "simple ASCII",
			input: []byte{'H', 'e', 'l', 'l', 'o'},
			want:  "Hello",
		},
		{
			name:  "ASCII with space",
			input: []byte{'W', 'o', 'r', 'l', 'd', ' '},
			want:  "World ",
		},
		{
			name:  "byte value 0",
			input: []byte{0, 'A'},
			want:  "\u0000A", // Null character followed by A
		},
		{
			name:  "byte value 255",
			input: []byte{255, 'B'},
			want:  string([]rune{0xFF, 'B'}), // Rune U+00FF (ÿ) followed by B
		},
		{
			name:  "all printable ASCII bytes (subset)",
			input: []byte{32, 33, 65, 97, 126},
			want:  " !Aa~",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BytesToString(tt.input)
			if got != tt.want {
				t.Errorf("BytesToString() got = %v, want %v", got, tt.want)
				// For debugging characters
				t.Logf("Got runes: %v", []rune(got))
				t.Logf("Want runes: %v", []rune(tt.want))
			}
		})
	}
}

// TestStringToBytes tests the StringToBytes function.
func TestStringToBytes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{
			name:  "empty string",
			input: "",
			want:  []byte{},
		},
		{
			name:  "simple ASCII",
			input: "Hello World 123!!",
			want: []byte{
				'H',
				'e',
				'l',
				'l',
				'o',
				' ',
				'W',
				'o',
				'r',
				'l',
				'd',
				' ',
				'1',
				'2',
				'3',
				'!',
				'!',
			},
		},
		{
			name:  "ASCII with space",
			input: "World ",
			want:  []byte{'W', 'o', 'r', 'l', 'd', ' '},
		},
		{
			name:  "U+0000 (null char)",
			input: "\u0000A",
			want:  []byte{0, 'A'}, // Truncated from rune(0)
		},
		{
			name:  "U+00FF (ÿ)",
			input: string([]rune{0xFF, 'B'}), // "ÿB"
			want:  []byte{0xFF, 'B'},         // Truncated from rune(0xFF)
		},
		{
			name:  "Euro symbol € (U+20AC) - Truncation check",
			input: "€",
			want:  []byte{0xAC}, // Java (byte)'€' is 0xAC
		},
		{
			name:  "Vietnamese đ (U+0111) - Truncation check",
			input: "đ",
			want:  []byte{0x11}, // Java (byte)'đ' (0x0111) is 0x11
		},
		{
			name:  "Full-width F Ｆ (U+FF46) - Truncation check",
			input: string([]rune{0xFF46}),
			want:  []byte{0x46},
		},
		{
			name:  "Mixed ASCII and Unicode with truncation",
			input: string([]rune{'A', 0x00FC, 'B', 0x20AC, 'C', 0xFF46, 'D'}),
			want:  []byte{0x41, 0xFC, 0x42, 0xAC, 0x43, 0x46, 0x44},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringToBytes(tt.input)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("StringToBytes() failed for input '%s'", tt.input)
				t.Logf("Got bytes (decimal): %v", got)
				t.Logf("Got bytes (hex): %x", got)
				t.Logf("Want bytes (decimal): %v", tt.want)
				t.Logf("Want bytes (hex): %x", tt.want)
				// So sánh từng byte một
				for i := 0; i < len(tt.want); i++ {
					if i >= len(got) {
						t.Errorf(
							"Byte mismatch at index %d: got length %d, want length %d",
							i,
							len(got),
							len(tt.want),
						)
						break
					}
					if got[i] != tt.want[i] {
						t.Errorf(
							"Byte mismatch at index %d: got %d (0x%x), want %d (0x%x)",
							i,
							got[i],
							got[i],
							tt.want[i],
							tt.want[i],
						)
					}
				}
				if len(got) != len(tt.want) {
					t.Errorf("Length mismatch: got %d, want %d", len(got), len(tt.want))
				}
			}
		})
	}
}

// TestStringToBytesInternal tests the internal helper function.
func TestStringToBytesInternal(t *testing.T) {
	tests := []struct {
		name        string
		inputRunes  []rune
		targetBytes []byte
		offset      int
		wantBytes   []byte
		wantReturn  []byte
	}{
		{
			name:        "simple copy to offset 0",
			inputRunes:  []rune("Hi"),
			targetBytes: make([]byte, 2),
			offset:      0,
			wantBytes:   []byte{'H', 'i'},
			wantReturn:  []byte{'H', 'i'},
		},
		{
			name:        "copy to offset 1",
			inputRunes:  []rune("Go"),
			targetBytes: []byte{'X', 'Y', 'Z'},
			offset:      1,
			wantBytes:   []byte{'X', 'G', 'o'},
			wantReturn:  []byte{'X', 'G', 'o'},
		},
		{
			name:        "empty string to buffer",
			inputRunes:  []rune(""),
			targetBytes: make([]byte, 3),
			offset:      1,
			wantBytes:   make([]byte, 3),
			wantReturn:  make([]byte, 3),
		},
		{
			name:        "string too long for buffer and offset",
			inputRunes:  []rune("Test"),
			targetBytes: make([]byte, 3),
			offset:      1,
			wantBytes:   nil,
			wantReturn:  nil,
		},
		{
			name:        "nil target buffer with non-empty string",
			inputRunes:  []rune("Hello"),
			targetBytes: nil,
			offset:      0,
			wantBytes:   nil,
			wantReturn:  nil,
		},
		{
			name:        "nil target buffer with empty string",
			inputRunes:  []rune(""),
			targetBytes: nil,
			offset:      0,
			wantBytes:   nil,
			wantReturn:  nil,
		},
		{
			name:        "offset out of bounds (negative)",
			inputRunes:  []rune("A"),
			targetBytes: make([]byte, 1),
			offset:      -1,
			wantReturn:  nil,
		},
		{
			name:        "offset out of bounds (positive, too large)",
			inputRunes:  []rune("A"),
			targetBytes: make([]byte, 1),
			offset:      2,
			wantReturn:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalTargetBytes := make([]byte, len(tt.targetBytes))
			copy(originalTargetBytes, tt.targetBytes)

			gotReturn := stringToBytes(
				tt.inputRunes,
				tt.targetBytes,
				tt.offset,
			)

			if !bytes.Equal(gotReturn, tt.wantReturn) {
				t.Errorf(
					"stringToBytesInternal() returned %v (hex: %x), want %v (hex: %x)",
					gotReturn,
					gotReturn,
					tt.wantReturn,
					tt.wantReturn,
				)
			}

			if tt.wantBytes != nil {
				if !bytes.Equal(tt.targetBytes, tt.wantBytes) {
					t.Errorf(
						"stringToBytesInternal() targetBytes became %v (hex: %x), want %v (hex: %x)",
						tt.targetBytes,
						tt.targetBytes,
						tt.wantBytes,
						tt.wantBytes,
					)
				}
			} else if gotReturn != nil {
				if len(tt.targetBytes) > 0 && len(gotReturn) > 0 && &tt.targetBytes[0] != &gotReturn[0] && !bytes.Equal(tt.targetBytes, originalTargetBytes) {
					t.Errorf("stringToBytesInternal() targetBytes was modified to %v, expected to remain %v", tt.targetBytes, originalTargetBytes)
				}
			}
		})
	}
}

func TestRuneToByteConversion(t *testing.T) {
	r := rune(0xFF46)
	b := byte(r)
	expectedByte := byte(0x46)

	t.Logf("Rune value: 0x%X", r)
	t.Logf("Converted byte value (decimal): %d", b)
	t.Logf("Converted byte value (hex): 0x%X", b)
	t.Logf("Expected byte value (decimal): %d", expectedByte)
	t.Logf("Expected byte value (hex): 0x%X", expectedByte)

	if b != expectedByte {
		t.Errorf("Direct rune to byte conversion failed. Got 0x%X, want 0x%X", b, expectedByte)
	}
}

func TestInternalHelperDirectlyWithFF46(t *testing.T) {
	inputRunes := []rune{0xFF46}
	targetBytes := make([]byte, 1)
	offset := 0

	t.Logf("Runes for internal helper: 0x%X", inputRunes[0])

	resultBytes := stringToBytes(inputRunes, targetBytes, offset)

	expectedByte := byte(0x46)
	if len(resultBytes) == 0 {
		t.Errorf(
			"Internal helper direct call failed. ResultBytes is nil or empty, want byte 0x%X",
			expectedByte,
		)
	} else if resultBytes[0] != expectedByte {
		t.Errorf(
			"Internal helper direct call failed. Got byte 0x%X, want 0x%X",
			resultBytes[0],
			expectedByte,
		)
		t.Logf("Result bytes (decimal): %v", resultBytes)
		t.Logf("Result bytes (hex): %x", resultBytes)
	}
}
