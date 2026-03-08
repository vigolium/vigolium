package xss_light_scanner

import (
	"fmt"
	"testing"
)

// Helper to create a mock payload with known segments for testing
func mockPayloadWithSegments(segments []string, chars []byte) *CanaryPayload {
	if len(segments) != len(chars)+1 {
		panic("segments length should be chars length + 1")
	}

	charMap := make(map[byte]int)
	charOffsets := make(map[byte]int)

	payload := segments[0]
	offset := len(segments[0])

	for i, ch := range chars {
		charMap[ch] = i
		charOffsets[ch] = offset
		payload += string(ch) + segments[i+1]
		offset += 1 + len(segments[i+1])
	}

	return &CanaryPayload{
		FullPayload: payload,
		Canary:      segments[0],
		Segments:    segments,
		CharMap:     charMap,
		CharOffsets: charOffsets,
	}
}

// ============================================================================
// Single Character Transform Detection Tests
// ============================================================================

func TestTransformAnalyzer_DetectCharTransform_Passed(t *testing.T) {
	ta := NewTransformAnalyzer()
	payload := mockPayloadWithSegments([]string{"abc1", "def2"}, []byte{'\''})

	// Input: abc1'def2 → Response: abc1'def2 (unchanged)
	matchedBytes := []byte("abc1'def2")

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

	ct := analysis.GetCharTransform('\'')
	if ct == nil {
		t.Fatal("Expected transform for single quote")
	}
	if ct.Transform != TransformPassed {
		t.Errorf("Transform = %v, want TransformPassed", ct.Transform)
	}
	if ct.OutputSeq != "'" {
		t.Errorf("OutputSeq = %q, want %q", ct.OutputSeq, "'")
	}
}

func TestTransformAnalyzer_DetectCharTransform_BackslashEsc(t *testing.T) {
	ta := NewTransformAnalyzer()
	payload := mockPayloadWithSegments([]string{"abc1", "def2"}, []byte{'\''})

	// Input: abc1'def2 → Response: abc1\'def2 (backslash escaped)
	matchedBytes := []byte("abc1\\'def2")

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, JSStringSQBreakout, 0)

	ct := analysis.GetCharTransform('\'')
	if ct == nil {
		t.Fatal("Expected transform for single quote")
	}
	if ct.Transform != TransformBackslashEsc {
		t.Errorf("Transform = %v, want TransformBackslashEsc", ct.Transform)
	}
	if ct.OutputSeq != "\\'" {
		t.Errorf("OutputSeq = %q, want %q", ct.OutputSeq, "\\'")
	}
}

func TestTransformAnalyzer_DetectCharTransform_HTMLEncoded(t *testing.T) {
	ta := NewTransformAnalyzer()

	tests := []struct {
		name     string
		char     byte
		encoded  string
		segments []string
	}{
		{"SingleQuote_Numeric", '\'', "&#39;", []string{"abc1", "def2"}},
		{"SingleQuote_Named", '\'', "&apos;", []string{"xyz1", "uvw2"}},
		{"DoubleQuote_Numeric", '"', "&#34;", []string{"aaa1", "bbb2"}},
		{"DoubleQuote_Named", '"', "&quot;", []string{"ccc1", "ddd2"}},
		{"LessThan_Numeric", '<', "&#60;", []string{"eee1", "fff2"}},
		{"LessThan_Named", '<', "&lt;", []string{"ggg1", "hhh2"}},
		{"GreaterThan_Numeric", '>', "&#62;", []string{"iii1", "jjj2"}},
		{"GreaterThan_Named", '>', "&gt;", []string{"kkk1", "lll2"}},
		{"Backtick_Numeric", '`', "&#96;", []string{"mmm1", "nnn2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mockPayloadWithSegments(tt.segments, []byte{tt.char})
			matchedBytes := []byte(tt.segments[0] + tt.encoded + tt.segments[1])

			analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

			ct := analysis.GetCharTransform(tt.char)
			if ct == nil {
				t.Fatalf("Expected transform for %q", string(tt.char))
			}
			if ct.Transform != TransformHTMLEncoded {
				t.Errorf("Transform = %v, want TransformHTMLEncoded", ct.Transform)
			}
			if ct.OutputSeq != tt.encoded {
				t.Errorf("OutputSeq = %q, want %q", ct.OutputSeq, tt.encoded)
			}
		})
	}
}

func TestTransformAnalyzer_DetectCharTransform_URLEncoded(t *testing.T) {
	ta := NewTransformAnalyzer()

	tests := []struct {
		name     string
		char     byte
		encoded  string
		segments []string
	}{
		{"SingleQuote", '\'', "%27", []string{"abc1", "def2"}},
		{"DoubleQuote", '"', "%22", []string{"xyz1", "uvw2"}},
		{"LessThan", '<', "%3C", []string{"aaa1", "bbb2"}},
		{"GreaterThan", '>', "%3E", []string{"ccc1", "ddd2"}},
		{"Backtick", '`', "%60", []string{"eee1", "fff2"}},
		{"Space", ' ', "%20", []string{"ggg1", "hhh2"}},
		{"Slash", '/', "%2F", []string{"iii1", "jjj2"}},
		{"Equal", '=', "%3D", []string{"kkk1", "lll2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mockPayloadWithSegments(tt.segments, []byte{tt.char})
			matchedBytes := []byte(tt.segments[0] + tt.encoded + tt.segments[1])

			analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

			ct := analysis.GetCharTransform(tt.char)
			if ct == nil {
				t.Fatalf("Expected transform for %q", string(tt.char))
			}
			if ct.Transform != TransformURLEncoded {
				t.Errorf("Transform = %v, want TransformURLEncoded", ct.Transform)
			}
		})
	}
}

func TestTransformAnalyzer_DetectCharTransform_Removed(t *testing.T) {
	ta := NewTransformAnalyzer()
	payload := mockPayloadWithSegments([]string{"abc1", "def2"}, []byte{'\''})

	// Input: abc1'def2 → Response: abc1def2 (quote removed)
	matchedBytes := []byte("abc1def2")

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

	ct := analysis.GetCharTransform('\'')
	if ct == nil {
		t.Fatal("Expected transform for single quote")
	}
	if ct.Transform != TransformRemoved {
		t.Errorf("Transform = %v, want TransformRemoved", ct.Transform)
	}
	if ct.OutputSeq != "" {
		t.Errorf("OutputSeq = %q, want empty", ct.OutputSeq)
	}
}

// ============================================================================
// Sequence Transform Detection Tests (for Phase 2)
// ============================================================================

func TestTransformAnalyzer_DetectSequenceTransform_Passed(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Payload has \' as sequence
	segments := []string{"abc1", "def2"}
	payload := &CanaryPayload{
		FullPayload: "abc1\\'def2",
		Canary:      "abc1",
		Segments:    segments,
		CharMap:     map[byte]int{'\\': 0},
		CharOffsets: map[byte]int{'\\': 4},
	}

	// Input: abc1\'def2 → Response: abc1\'def2 (unchanged)
	matchedBytes := []byte("abc1\\'def2")

	transforms := ta.AnalyzeSequenceTransforms(matchedBytes, payload, []string{"\\'"})

	ct := transforms["\\'"]
	if ct == nil {
		t.Fatal("Expected transform for \\' sequence")
	}
	if ct.Transform != TransformPassed {
		t.Errorf("Transform = %v, want TransformPassed", ct.Transform)
	}
}

func TestTransformAnalyzer_DetectSequenceTransform_DoubleBackslash(t *testing.T) {
	ta := NewTransformAnalyzer()

	segments := []string{"abc1", "def2"}
	payload := &CanaryPayload{
		FullPayload: "abc1\\'def2",
		Canary:      "abc1",
		Segments:    segments,
		CharMap:     map[byte]int{'\\': 0},
		CharOffsets: map[byte]int{'\\': 4},
	}

	// Input: abc1\'def2 → Response: abc1\\'def2 (double backslash - EXPLOITABLE!)
	matchedBytes := []byte("abc1\\\\'def2")

	transforms := ta.AnalyzeSequenceTransforms(matchedBytes, payload, []string{"\\'"})

	ct := transforms["\\'"]
	if ct == nil {
		t.Fatal("Expected transform for \\' sequence")
	}
	if ct.Transform != TransformDoubleBackslash {
		t.Errorf("Transform = %v, want TransformDoubleBackslash", ct.Transform)
	}
	if ct.OutputSeq != "\\\\'" {
		t.Errorf("OutputSeq = %q, want %q", ct.OutputSeq, "\\\\'")
	}
}

func TestTransformAnalyzer_DetectSequenceTransform_TripleBackslash(t *testing.T) {
	ta := NewTransformAnalyzer()

	segments := []string{"abc1", "def2"}
	payload := &CanaryPayload{
		FullPayload: "abc1\\'def2",
		Canary:      "abc1",
		Segments:    segments,
		CharMap:     map[byte]int{'\\': 0},
		CharOffsets: map[byte]int{'\\': 4},
	}

	// Input: abc1\'def2 → Response: abc1\\\'def2 (triple backslash - NOT exploitable)
	matchedBytes := []byte("abc1\\\\\\'def2")

	transforms := ta.AnalyzeSequenceTransforms(matchedBytes, payload, []string{"\\'"})

	ct := transforms["\\'"]
	if ct == nil {
		t.Fatal("Expected transform for \\' sequence")
	}
	if ct.Transform != TransformTripleBackslash {
		t.Errorf("Transform = %v, want TransformTripleBackslash", ct.Transform)
	}
}

func TestTransformAnalyzer_DetectSequenceTransform_SingleQuoteOnly(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Test single sequence: \'
	payload := BuildBatchedSecondaryPayload([]string{"\\'"})
	if payload == nil {
		t.Fatal("Failed to build batched payload")
	}

	// Test double backslash: \' → \\'
	responseStr := payload.Segments[0] + "\\\\'" + payload.Segments[1]
	matchedBytes := []byte(responseStr)

	transforms := ta.AnalyzeSequenceTransforms(matchedBytes, payload, []string{"\\'"})

	ctSQ := transforms["\\'"]
	if ctSQ == nil {
		t.Fatal("Expected transform for \\' sequence")
	}
	if ctSQ.Transform != TransformDoubleBackslash {
		t.Errorf("\\' Transform = %v, want TransformDoubleBackslash", ctSQ.Transform)
	}
}

func TestTransformAnalyzer_DetectSequenceTransform_DoubleQuoteOnly(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Test single sequence: \"
	payload := BuildBatchedSecondaryPayload([]string{"\\\""})
	if payload == nil {
		t.Fatal("Failed to build batched payload")
	}

	// Test passed: \" → \"
	responseStr := payload.Segments[0] + "\\\"" + payload.Segments[1]
	matchedBytes := []byte(responseStr)

	transforms := ta.AnalyzeSequenceTransforms(matchedBytes, payload, []string{"\\\""})

	ctDQ := transforms["\\\""]
	if ctDQ == nil {
		t.Fatal("Expected transform for \\\" sequence")
	}
	if ctDQ.Transform != TransformPassed {
		t.Errorf("\\\" Transform = %v, want TransformPassed", ctDQ.Transform)
	}
}

// ============================================================================
// Multiple Character Analysis Tests
// ============================================================================

func TestTransformAnalyzer_AnalyzeTransforms_MultipleChars(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Payload: seg0'seg1"seg2<seg3>seg4
	segments := []string{"abc1", "def2", "ghi3", "jkl4", "mno5"}
	chars := []byte{'\'', '"', '<', '>'}
	payload := mockPayloadWithSegments(segments, chars)

	// Response: ' escaped, " passed, < encoded, > passed
	matchedBytes := []byte("abc1\\'def2\"ghi3&lt;jkl4>mno5")

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

	tests := []struct {
		char     byte
		expected TransformType
	}{
		{'\'', TransformBackslashEsc},
		{'"', TransformPassed},
		{'<', TransformHTMLEncoded},
		{'>', TransformPassed},
	}

	for _, tt := range tests {
		ct := analysis.GetCharTransform(tt.char)
		if ct == nil {
			t.Errorf("Missing transform for %q", string(tt.char))
			continue
		}
		if ct.Transform != tt.expected {
			t.Errorf("Char %q: Transform = %v, want %v", string(tt.char), ct.Transform, tt.expected)
		}
	}
}

func TestTransformAnalyzer_AnalyzeTransforms_AllPrimaryChars(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Use real primary payload structure with dynamic segments
	chars := BreakoutChars // ' " ` < > (space) = / $ { } -
	segments := make([]string, len(chars)+1)
	for i := range segments {
		segments[i] = fmt.Sprintf("s%d%c%c", i, 'a'+byte(i%26), 'a'+byte((i+1)%26))
	}
	payload := mockPayloadWithSegments(segments, chars)

	// All chars pass through unchanged
	matchedBytes := []byte(payload.FullPayload)

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

	for _, ch := range BreakoutChars {
		ct := analysis.GetCharTransform(ch)
		if ct == nil {
			t.Errorf("Missing transform for %q", string(ch))
			continue
		}
		if ct.Transform != TransformPassed {
			t.Errorf("Char %q: Transform = %v, want TransformPassed", string(ch), ct.Transform)
		}
	}
}

// ============================================================================
// Edge Cases Tests
// ============================================================================

func TestTransformAnalyzer_DetectCharTransform_EmptySegments(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Payload with empty or missing segment info
	payload := &CanaryPayload{
		FullPayload: "test",
		Canary:      "test",
		Segments:    []string{},
		CharMap:     map[byte]int{},
		CharOffsets: map[byte]int{},
	}

	matchedBytes := []byte("test'")

	// Should not panic, just return empty analysis
	analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

	// No char transforms should be detected
	if analysis.GetCharTransform('\'') != nil {
		t.Error("Should not detect transform without segment info")
	}
}

func TestTransformAnalyzer_DetectSequenceTransform_EmptySequence(t *testing.T) {
	ta := NewTransformAnalyzer()

	payload := &CanaryPayload{
		FullPayload: "abc",
		Canary:      "abc",
		Segments:    []string{"abc"},
		CharMap:     map[byte]int{},
		CharOffsets: map[byte]int{},
	}

	matchedBytes := []byte("abc")

	// Empty sequence should be handled gracefully
	transforms := ta.AnalyzeSequenceTransforms(matchedBytes, payload, []string{""})

	if len(transforms) != 0 {
		t.Error("Empty sequence should not produce transforms")
	}
}

func TestTransformAnalyzer_CaseSensitiveHTMLEncoding(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Test both upper and lowercase hex encoding
	tests := []struct {
		name    string
		encoded string
	}{
		{"LowerHex", "&#x3c;"},
		{"UpperHex", "&#x3C;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mockPayloadWithSegments([]string{"abc1", "def2"}, []byte{'<'})
			matchedBytes := []byte("abc1" + tt.encoded + "def2")

			analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

			ct := analysis.GetCharTransform('<')
			if ct == nil {
				t.Fatal("Expected transform for <")
			}
			if ct.Transform != TransformHTMLEncoded {
				t.Errorf("Transform = %v, want TransformHTMLEncoded", ct.Transform)
			}
		})
	}
}

func TestTransformAnalyzer_SpaceURLEncoding(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Space can be encoded as %20 or +
	tests := []struct {
		name    string
		encoded string
	}{
		{"Percent20", "%20"},
		{"Plus", "+"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := mockPayloadWithSegments([]string{"abc1", "def2"}, []byte{' '})
			matchedBytes := []byte("abc1" + tt.encoded + "def2")

			analysis := ta.AnalyzeTransforms(matchedBytes, payload, HTMLGeneric, 0)

			ct := analysis.GetCharTransform(' ')
			if ct == nil {
				t.Fatal("Expected transform for space")
			}
			if ct.Transform != TransformURLEncoded {
				t.Errorf("Transform = %v, want TransformURLEncoded", ct.Transform)
			}
		})
	}
}

// ============================================================================
// Integration with EscapeAnalysis Tests
// ============================================================================

func TestTransformAnalyzer_AnalyzeTransforms_ReturnsValidEscapeAnalysis(t *testing.T) {
	ta := NewTransformAnalyzer()

	segments := []string{"abc1", "def2", "ghi3"}
	payload := mockPayloadWithSegments(segments, []byte{'\'', ';'})

	// ' passed, ; passed
	matchedBytes := []byte("abc1'def2;ghi3")

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, JSStringSQBreakout, 100)

	// Verify EscapeAnalysis fields
	if analysis.Context != JSStringSQBreakout {
		t.Errorf("Context = %v, want JSStringSQBreakout", analysis.Context)
	}
	if analysis.Offset != 100 {
		t.Errorf("Offset = %d, want 100", analysis.Offset)
	}
	if analysis.PayloadSent != payload.FullPayload {
		t.Errorf("PayloadSent = %q, want %q", analysis.PayloadSent, payload.FullPayload)
	}

	// Should be exploitable (quote and terminator passed)
	if !analysis.IsExploitable() {
		t.Error("Should be exploitable with ' and ; passed")
	}
}

func TestTransformAnalyzer_AnalyzeTransforms_JSStringEscaped(t *testing.T) {
	ta := NewTransformAnalyzer()

	segments := []string{"abc1", "def2", "ghi3"}
	payload := mockPayloadWithSegments(segments, []byte{'\'', ';'})

	// ' escaped, ; passed
	matchedBytes := []byte("abc1\\'def2;ghi3")

	analysis := ta.AnalyzeTransforms(matchedBytes, payload, JSStringSQBreakout, 0)

	// Should NOT be exploitable (quote escaped)
	if analysis.IsExploitable() {
		t.Error("Should NOT be exploitable with ' escaped")
	}

	// But HasBackslashEscaped should be true
	if !analysis.HasBackslashEscaped('\'') {
		t.Error("Should detect backslash escape for '")
	}
}
