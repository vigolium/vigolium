package xss_light_scanner

import (
	"strings"
	"testing"
)

func TestGenerateRandomSegment(t *testing.T) {
	// Generate multiple segments and verify format
	for i := 0; i < 100; i++ {
		seg := generateRandomSegment()

		if len(seg) != 4 {
			t.Errorf("generateRandomSegment() length = %d, want 4", len(seg))
		}

		// First char should be a-z
		if seg[0] < 'a' || seg[0] > 'z' {
			t.Errorf("generateRandomSegment() first char = %c, want a-z", seg[0])
		}

		// Remaining chars should be alphanumeric
		for j := 1; j < 4; j++ {
			ch := seg[j]
			isLower := ch >= 'a' && ch <= 'z'
			isDigit := ch >= '0' && ch <= '9'
			if !isLower && !isDigit {
				t.Errorf("generateRandomSegment()[%d] = %c, want alphanumeric", j, ch)
			}
		}
	}
}

func TestGenerateRandomSegment_Uniqueness(t *testing.T) {
	// Generate many segments and verify they're reasonably unique
	segments := make(map[string]bool)
	collisions := 0

	for i := 0; i < 1000; i++ {
		seg := generateRandomSegment()
		if segments[seg] {
			collisions++
		}
		segments[seg] = true
	}

	// With 4 chars (26 letters + 26*36*36*36 combinations), collisions should be rare
	if collisions > 10 {
		t.Errorf("Too many collisions: %d out of 1000", collisions)
	}
}

func TestGeneratePrimary(t *testing.T) {
	payload := GeneratePrimary()

	// Verify all fields are set
	if payload == nil {
		t.Fatal("GeneratePrimary() returned nil")
	}

	if payload.FullPayload == "" {
		t.Error("GeneratePrimary().FullPayload is empty")
	}

	if payload.Canary == "" {
		t.Error("GeneratePrimary().Canary is empty")
	}

	expectedSegments := len(BreakoutChars) + 1
	if len(payload.Segments) != expectedSegments {
		t.Errorf("GeneratePrimary().Segments length = %d, want %d", len(payload.Segments), expectedSegments)
	}

	// Verify canary is the first segment
	if payload.Canary != payload.Segments[0] {
		t.Error("GeneratePrimary().Canary should be first segment")
	}

	// Verify payload starts with canary
	if !strings.HasPrefix(payload.FullPayload, payload.Canary) {
		t.Error("GeneratePrimary().FullPayload should start with canary")
	}
}

func TestGeneratePrimary_ContainsAllBreakoutChars(t *testing.T) {
	payload := GeneratePrimary()

	for _, ch := range BreakoutChars {
		if !strings.ContainsRune(payload.FullPayload, rune(ch)) {
			t.Errorf("GeneratePrimary().FullPayload missing char %c", ch)
		}
	}
}

func TestGeneratePrimary_CharOffsets(t *testing.T) {
	payload := GeneratePrimary()

	for _, ch := range BreakoutChars {
		offset := payload.GetCharOffset(ch)
		if offset < 0 {
			t.Errorf("GetCharOffset(%c) = %d, want >= 0", ch, offset)
			continue
		}

		// Verify the character is actually at that offset
		if offset >= len(payload.FullPayload) {
			t.Errorf("GetCharOffset(%c) = %d, exceeds payload length", ch, offset)
			continue
		}

		if payload.FullPayload[offset] != ch {
			t.Errorf("FullPayload[%d] = %c, want %c", offset, payload.FullPayload[offset], ch)
		}
	}
}

func TestGeneratePrimary_CharMap(t *testing.T) {
	payload := GeneratePrimary()

	if len(payload.CharMap) != len(BreakoutChars) {
		t.Errorf("CharMap length = %d, want %d", len(payload.CharMap), len(BreakoutChars))
	}

	for i, ch := range BreakoutChars {
		if idx, ok := payload.CharMap[ch]; !ok || idx != i {
			t.Errorf("CharMap[%c] = %d, want %d", ch, idx, i)
		}
	}
}

func TestGeneratePrimary_SegmentStructure(t *testing.T) {
	payload := GeneratePrimary()

	// Verify structure: {R4}'{R4}"{R4}`{R4}<{R4}>{R4} {R4}={R4}/{R4}
	expected := payload.Segments[0]
	for i, ch := range BreakoutChars {
		expected += string(ch) + payload.Segments[i+1]
	}

	if payload.FullPayload != expected {
		t.Errorf("FullPayload structure mismatch:\ngot:  %s\nwant: %s", payload.FullPayload, expected)
	}
}

func TestCanaryPayload_ContainsCanary(t *testing.T) {
	payload := GeneratePrimary()

	// Should contain its own canary
	if !payload.ContainsCanary(payload.Canary) {
		t.Error("ContainsCanary should return true for own canary")
	}

	// Should not contain random canary
	if payload.ContainsCanary("zzzz") {
		t.Error("ContainsCanary should return false for random canary")
	}
}

func TestCanaryPayload_GetCharOffset_NotFound(t *testing.T) {
	payload := GeneratePrimary()

	// Primary payload shouldn't have secondary chars
	offset := payload.GetCharOffset(';')
	if offset != -1 {
		t.Errorf("GetCharOffset(';') = %d, want -1", offset)
	}
}

func TestCanaryPayload_GetSegmentBefore(t *testing.T) {
	payload := GeneratePrimary()

	for i, ch := range BreakoutChars {
		seg := payload.GetSegmentBefore(ch)
		expected := payload.Segments[i]

		if seg != expected {
			t.Errorf("GetSegmentBefore(%c) = %s, want %s", ch, seg, expected)
		}
	}
}

func TestCanaryPayload_GetSegmentBefore_NotFound(t *testing.T) {
	payload := GeneratePrimary()

	// Secondary char not in primary payload
	seg := payload.GetSegmentBefore(';')
	if seg != "" {
		t.Errorf("GetSegmentBefore(';') = %s, want empty", seg)
	}
}

func TestCanaryPayload_GetSegmentAfter(t *testing.T) {
	payload := GeneratePrimary()

	for i, ch := range BreakoutChars {
		seg := payload.GetSegmentAfter(ch)
		expected := payload.Segments[i+1]

		if seg != expected {
			t.Errorf("GetSegmentAfter(%c) = %s, want %s", ch, seg, expected)
		}
	}
}

func TestCanaryPayload_GetSegmentAfter_NotFound(t *testing.T) {
	payload := GeneratePrimary()

	// Secondary char not in primary payload
	seg := payload.GetSegmentAfter(';')
	if seg != "" {
		t.Errorf("GetSegmentAfter(';') = %s, want empty", seg)
	}
}

func TestBreakoutChars(t *testing.T) {
	// Now includes: quotes, angle brackets, space, equals, slash, template chars (${}), dash
	expected := []byte{'\'', '"', '`', '<', '>', ' ', '=', '/', '$', '{', '}', '-'}

	if len(BreakoutChars) != len(expected) {
		t.Errorf("BreakoutChars length = %d, want %d", len(BreakoutChars), len(expected))
	}

	for i, ch := range expected {
		if BreakoutChars[i] != ch {
			t.Errorf("BreakoutChars[%d] = %c (0x%02x), want %c (0x%02x)", i, BreakoutChars[i], BreakoutChars[i], ch, ch)
		}
	}
}

func TestGeneratePrimary_Deterministic(t *testing.T) {
	// Each call should generate different payload
	p1 := GeneratePrimary()
	p2 := GeneratePrimary()

	// Canaries should be different (very high probability)
	if p1.Canary == p2.Canary {
		t.Log("Warning: Two consecutive GeneratePrimary() calls generated same canary (unlikely but possible)")
	}

	// Full payloads should be different
	if p1.FullPayload == p2.FullPayload {
		t.Error("Two consecutive GeneratePrimary() calls generated identical payloads")
	}
}

func TestGeneratePrimary_PayloadLength(t *testing.T) {
	payload := GeneratePrimary()

	// Expected length: (numChars+1) segments * 4 chars + numChars breakout chars
	numChars := len(BreakoutChars)
	expectedLen := (numChars+1)*4 + numChars
	if len(payload.FullPayload) != expectedLen {
		t.Errorf("FullPayload length = %d, want %d", len(payload.FullPayload), expectedLen)
	}
}
