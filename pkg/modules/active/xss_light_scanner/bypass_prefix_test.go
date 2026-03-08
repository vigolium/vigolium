package xss_light_scanner

import (
	"testing"
)

// ============================================================================
// BypassPrefix Tests
// ============================================================================

func TestBypassPrefix_HasPrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefix   BypassPrefix
		expected bool
	}{
		{"none", BypassPrefix{Name: "none", Bytes: nil}, false},
		{"null", BypassPrefix{Name: "null", Bytes: []byte{0x00}}, true},
		{"ff", BypassPrefix{Name: "ff", Bytes: []byte{0xff}}, true},
		{"crlf", BypassPrefix{Name: "crlf", Bytes: []byte{0x0d, 0x0a}}, true},
		{"emptyBytes", BypassPrefix{Name: "empty", Bytes: []byte{}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.prefix.HasPrefix(); got != tt.expected {
				t.Errorf("HasPrefix() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBypassPrefix_String(t *testing.T) {
	tests := []struct {
		prefix   BypassPrefix
		expected string
	}{
		{BypassPrefix{Name: "none", Bytes: nil}, "none"},
		{BypassPrefix{Name: "null", Bytes: []byte{0x00}}, "null"},
		{BypassPrefix{Name: "ff", Bytes: []byte{0xff}}, "ff"},
		{BypassPrefix{Name: "crlf", Bytes: []byte{0x0d, 0x0a}}, "crlf"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.prefix.String(); got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBypassPrefixes_Count(t *testing.T) {
	// Verify we have 4 bypass prefixes
	if len(BypassPrefixes) != 4 {
		t.Errorf("Expected 4 bypass prefixes, got %d", len(BypassPrefixes))
	}
}

func TestBypassPrefixes_Order(t *testing.T) {
	// Verify order: none, null, ff, crlf
	expectedOrder := []string{"none", "null", "ff", "crlf"}

	for i, expected := range expectedOrder {
		if BypassPrefixes[i].Name != expected {
			t.Errorf("BypassPrefixes[%d].Name = %q, want %q", i, BypassPrefixes[i].Name, expected)
		}
	}
}

func TestBypassPrefixes_NoneIsFirst(t *testing.T) {
	// First prefix should be "none" (standard, no prefix)
	if BypassPrefixes[0].Name != "none" {
		t.Errorf("First prefix should be 'none', got %q", BypassPrefixes[0].Name)
	}
	if BypassPrefixes[0].HasPrefix() {
		t.Error("First prefix (none) should not have prefix bytes")
	}
}

func TestBypassPrefixes_ByteValues(t *testing.T) {
	tests := []struct {
		name          string
		expectedBytes []byte
	}{
		{"none", nil},
		{"null", []byte{0x00}},
		{"ff", []byte{0xff}},
		{"crlf", []byte{0x0d, 0x0a}},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := BypassPrefixes[i]
			if prefix.Name != tt.name {
				t.Fatalf("Index %d: expected name %q, got %q", i, tt.name, prefix.Name)
			}

			if tt.expectedBytes == nil {
				if prefix.Bytes != nil {
					t.Errorf("Expected nil bytes, got %v", prefix.Bytes)
				}
				return
			}

			if len(prefix.Bytes) != len(tt.expectedBytes) {
				t.Fatalf("Bytes length = %d, want %d", len(prefix.Bytes), len(tt.expectedBytes))
			}

			for j, b := range tt.expectedBytes {
				if prefix.Bytes[j] != b {
					t.Errorf("Bytes[%d] = 0x%02x, want 0x%02x", j, prefix.Bytes[j], b)
				}
			}
		})
	}
}

// ============================================================================
// GeneratePrimaryWithPrefix Tests
// ============================================================================

func TestGeneratePrimaryWithPrefix_NoPrefix(t *testing.T) {
	prefix := BypassPrefix{Name: "none", Bytes: nil}
	payload := GeneratePrimaryWithPrefix(prefix)

	// Should be same as regular GeneratePrimary
	standardPayload := GeneratePrimary()

	// Both should have same structure (different random segments but same format)
	if len(payload.Segments) != len(standardPayload.Segments) {
		t.Errorf("Segments length mismatch: %d vs %d", len(payload.Segments), len(standardPayload.Segments))
	}

	// Verify no prefix in payload
	if len(payload.FullPayload) == 0 {
		t.Fatal("Payload should not be empty")
	}

	// First char should be alphanumeric (segment start), not a prefix byte
	firstChar := payload.FullPayload[0]
	if firstChar == 0x00 || firstChar == 0xff || firstChar == 0x0d {
		t.Errorf("Payload should not start with prefix byte, got 0x%02x", firstChar)
	}
}

func TestGeneratePrimaryWithPrefix_NullByte(t *testing.T) {
	prefix := BypassPrefix{Name: "null", Bytes: []byte{0x00}}
	payload := GeneratePrimaryWithPrefix(prefix)

	// Should start with null byte
	if len(payload.FullPayload) == 0 {
		t.Fatal("Payload should not be empty")
	}

	if payload.FullPayload[0] != 0x00 {
		t.Errorf("Payload should start with null byte, got 0x%02x", payload.FullPayload[0])
	}

	// Verify char offsets are adjusted
	for ch, offset := range payload.CharOffsets {
		if offset < 1 {
			t.Errorf("Char '%c' offset %d should be >= 1 (prefix length)", ch, offset)
		}
	}
}

func TestGeneratePrimaryWithPrefix_FFByte(t *testing.T) {
	prefix := BypassPrefix{Name: "ff", Bytes: []byte{0xff}}
	payload := GeneratePrimaryWithPrefix(prefix)

	if len(payload.FullPayload) == 0 {
		t.Fatal("Payload should not be empty")
	}

	if payload.FullPayload[0] != 0xff {
		t.Errorf("Payload should start with 0xff, got 0x%02x", payload.FullPayload[0])
	}
}

func TestGeneratePrimaryWithPrefix_CRLF(t *testing.T) {
	prefix := BypassPrefix{Name: "crlf", Bytes: []byte{0x0d, 0x0a}}
	payload := GeneratePrimaryWithPrefix(prefix)

	if len(payload.FullPayload) < 2 {
		t.Fatal("Payload should have at least 2 bytes for CRLF")
	}

	if payload.FullPayload[0] != 0x0d || payload.FullPayload[1] != 0x0a {
		t.Errorf("Payload should start with CRLF (0x0d 0x0a), got 0x%02x 0x%02x",
			payload.FullPayload[0], payload.FullPayload[1])
	}

	// Verify char offsets are adjusted by 2
	for ch, offset := range payload.CharOffsets {
		if offset < 2 {
			t.Errorf("Char '%c' offset %d should be >= 2 (CRLF prefix length)", ch, offset)
		}
	}
}

func TestGeneratePrimaryWithPrefix_OffsetAdjustment(t *testing.T) {
	// Compare offsets with and without prefix
	noPrefixPayload := GeneratePrimary()
	prefixPayload := GeneratePrimaryWithPrefix(BypassPrefix{Name: "crlf", Bytes: []byte{0x0d, 0x0a}})

	// All offsets in prefix payload should be 2 more than in no-prefix payload
	// Note: We can't directly compare because segments are random, but we can verify structure

	// Verify prefix payload has adjusted offsets
	for ch := range prefixPayload.CharOffsets {
		prefixOffset := prefixPayload.CharOffsets[ch]
		noPrefixOffset := noPrefixPayload.CharOffsets[ch]

		// Since segments are random, we verify both payloads have the same chars mapped
		if _, exists := noPrefixPayload.CharOffsets[ch]; !exists {
			t.Errorf("Char '%c' missing in no-prefix payload", ch)
		}

		// Verify the char exists at the correct position in the payload
		if int(prefixOffset) >= len(prefixPayload.FullPayload) {
			t.Errorf("Char '%c' offset %d is out of bounds", ch, prefixOffset)
			continue
		}

		actualChar := prefixPayload.FullPayload[prefixOffset]
		if actualChar != ch {
			t.Errorf("Char at offset %d = %q, want %q", prefixOffset, string(actualChar), string(ch))
		}

		// Same check for no-prefix payload
		if int(noPrefixOffset) >= len(noPrefixPayload.FullPayload) {
			continue
		}
		actualCharNoPrefix := noPrefixPayload.FullPayload[noPrefixOffset]
		if actualCharNoPrefix != ch {
			t.Errorf("No-prefix: Char at offset %d = %q, want %q", noPrefixOffset, string(actualCharNoPrefix), string(ch))
		}
	}
}

// ============================================================================
// BuildBatchedSecondaryWithPrefix Tests
// ============================================================================

func TestBuildBatchedSecondaryWithPrefix_NoPrefix(t *testing.T) {
	prefix := BypassPrefix{Name: "none", Bytes: nil}
	sequences := []string{"\\'", "\\\""}
	payload := BuildBatchedSecondaryWithPrefix(sequences, prefix)

	if payload == nil {
		t.Fatal("Payload should not be nil")
	}

	// Should not start with prefix bytes
	firstChar := payload.FullPayload[0]
	if firstChar == 0x00 || firstChar == 0xff || firstChar == 0x0d {
		t.Errorf("Payload should not start with prefix byte, got 0x%02x", firstChar)
	}
}

func TestBuildBatchedSecondaryWithPrefix_NullByte(t *testing.T) {
	prefix := BypassPrefix{Name: "null", Bytes: []byte{0x00}}
	sequences := []string{"\\'"}
	payload := BuildBatchedSecondaryWithPrefix(sequences, prefix)

	if payload == nil {
		t.Fatal("Payload should not be nil")
	}

	if payload.FullPayload[0] != 0x00 {
		t.Errorf("Payload should start with null byte, got 0x%02x", payload.FullPayload[0])
	}
}

func TestBuildBatchedSecondaryWithPrefix_EmptySequences(t *testing.T) {
	prefix := BypassPrefix{Name: "null", Bytes: []byte{0x00}}
	payload := BuildBatchedSecondaryWithPrefix([]string{}, prefix)

	if payload != nil {
		t.Error("Payload should be nil for empty sequences")
	}
}

func TestBuildBatchedSecondaryWithPrefix_OffsetAdjustment(t *testing.T) {
	prefix := BypassPrefix{Name: "crlf", Bytes: []byte{0x0d, 0x0a}}
	sequences := []string{"\\'"}
	payload := BuildBatchedSecondaryWithPrefix(sequences, prefix)

	if payload == nil {
		t.Fatal("Payload should not be nil")
	}

	// Verify char at offset is correct (first char of sequence)
	for ch, offset := range payload.CharOffsets {
		if offset < 2 {
			t.Errorf("Char '%c' offset %d should be >= 2 (CRLF prefix length)", ch, offset)
		}

		if int(offset) >= len(payload.FullPayload) {
			t.Errorf("Offset %d out of bounds", offset)
			continue
		}

		actualChar := payload.FullPayload[offset]
		if actualChar != ch {
			t.Errorf("Char at offset %d = %q, want %q", offset, string(actualChar), string(ch))
		}
	}
}

// ============================================================================
// Sequential Prefix Strategy Tests
// ============================================================================

func TestBypassPrefixes_SequentialStrategy(t *testing.T) {
	// Verify that iterating through BypassPrefixes gives the correct order
	expectedNames := []string{"none", "null", "ff", "crlf"}

	for i, prefix := range BypassPrefixes {
		if prefix.Name != expectedNames[i] {
			t.Errorf("Prefix %d: expected %q, got %q", i, expectedNames[i], prefix.Name)
		}
	}
}
