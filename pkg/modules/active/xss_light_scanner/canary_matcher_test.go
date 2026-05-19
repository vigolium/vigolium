package xss_light_scanner

import (
	"strings"
	"testing"
)

func TestMatchMode_String(t *testing.T) {
	tests := []struct {
		mode     MatchMode
		expected string
	}{
		{MatchSimple, "simple"},
		{MatchHTMLDecode, "html_decode"},
		{MatchBackslashUnescape, "backslash_unescape"},
		{MatchBoth, "both"},
		{MatchMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("MatchMode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewEncodingAwareCanaryMatcher(t *testing.T) {
	payload := GeneratePrimary()
	matcher := NewEncodingAwareCanaryMatcher(payload)

	if matcher == nil {
		t.Fatal("NewEncodingAwareCanaryMatcher returned nil")
	}
	if matcher.payload != payload {
		t.Error("Matcher payload doesn't match input")
	}
}

func TestFindCanaryMatches_SimpleMatch(t *testing.T) {
	payload := GeneratePrimary()
	body := []byte("Before" + payload.FullPayload + "After")

	matches := FindCanaryMatches(body, payload)

	if len(matches) != 1 {
		t.Fatalf("FindCanaryMatches returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.DetectionMode != MatchSimple {
		t.Errorf("DetectionMode = %v, want MatchSimple", match.DetectionMode)
	}
	if match.StartOffset != 6 {
		t.Errorf("StartOffset = %d, want 6", match.StartOffset)
	}
}

func TestFindCanaryMatches_MultipleMatches(t *testing.T) {
	payload := GeneratePrimary()
	body := []byte(payload.FullPayload + "middle" + payload.FullPayload)

	matches := FindCanaryMatches(body, payload)

	if len(matches) != 2 {
		t.Fatalf("FindCanaryMatches returned %d matches, want 2", len(matches))
	}

	// First match at offset 0
	if matches[0].StartOffset != 0 {
		t.Errorf("First match StartOffset = %d, want 0", matches[0].StartOffset)
	}

	// Second match should be after "middle"
	expectedSecondOffset := len(payload.FullPayload) + 6
	if matches[1].StartOffset != expectedSecondOffset {
		t.Errorf("Second match StartOffset = %d, want %d", matches[1].StartOffset, expectedSecondOffset)
	}
}

func TestFindCanaryMatches_NoMatch(t *testing.T) {
	payload := GeneratePrimary()
	body := []byte("Some random content without the payload")

	matches := FindCanaryMatches(body, payload)

	if len(matches) != 0 {
		t.Errorf("FindCanaryMatches returned %d matches, want 0", len(matches))
	}
}

func TestFindCanaryMatches_HTMLEncodedMatch(t *testing.T) {
	payload := GeneratePrimary()

	// HTML encode < and >
	encodedPayload := strings.ReplaceAll(payload.FullPayload, "<", "&lt;")
	encodedPayload = strings.ReplaceAll(encodedPayload, ">", "&gt;")
	body := []byte(encodedPayload)

	matches := FindCanaryMatches(body, payload)

	if len(matches) == 0 {
		t.Fatal("FindCanaryMatches should find HTML-encoded payload")
	}

	// At least one match should be detected via HTML decode mode
	foundHTMLDecode := false
	for _, m := range matches {
		if m.DetectionMode == MatchHTMLDecode {
			foundHTMLDecode = true
			break
		}
	}

	if !foundHTMLDecode {
		t.Error("Should detect HTML-encoded match")
	}
}

func TestFindCanaryMatches_BackslashEscapedMatch(t *testing.T) {
	payload := GeneratePrimary()

	// Backslash escape quotes
	escapedPayload := strings.ReplaceAll(payload.FullPayload, "'", "\\'")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\"", "\\\"")
	body := []byte(escapedPayload)

	matches := FindCanaryMatches(body, payload)

	if len(matches) == 0 {
		t.Fatal("FindCanaryMatches should find backslash-escaped payload")
	}

	// At least one match should be detected via backslash unescape mode
	foundBackslash := false
	for _, m := range matches {
		if m.DetectionMode == MatchBackslashUnescape {
			foundBackslash = true
			break
		}
	}

	if !foundBackslash {
		t.Error("Should detect backslash-escaped match")
	}
}

func TestFindCanaryMatches_BothEncoded(t *testing.T) {
	payload := GeneratePrimary()

	// Apply both HTML encoding and backslash escaping
	encoded := strings.ReplaceAll(payload.FullPayload, "'", "\\'")
	encoded = strings.ReplaceAll(encoded, "<", "&lt;")
	body := []byte(encoded)

	matches := FindCanaryMatches(body, payload)

	if len(matches) == 0 {
		t.Fatal("FindCanaryMatches should find doubly-encoded payload")
	}
}

func TestHtmlDecode_StandardEntities(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"&lt;", "<"},
		{"&gt;", ">"},
		{"&quot;", "\""},
		{"&apos;", "'"},
		{"&grave;", "`"},
		{"&amp;", "&"},
		{"&lt;&gt;", "<>"},
		{"&lt;script&gt;", "<script>"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := htmlDecode([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("htmlDecode(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHtmlDecode_NumericEntities(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"&#39;", "'"},
		{"&#x27;", "'"},
		{"&#96;", "`"},
		{"&#x60;", "`"},
		{"&#60;", "<"},
		{"&#x3C;", "<"},
		{"&#62;", ">"},
		{"&#x3E;", ">"},
		{"&#97;", "a"},  // lowercase 'a'
		{"&#x61;", "a"}, // lowercase 'a'
		{"&#65;", "A"},  // uppercase 'A'
		{"&#x41;", "A"}, // uppercase 'A'
		{"&#10;", "\n"}, // newline
		{"&#13;", "\r"}, // carriage return
		{"&#9;", "\t"},  // tab
		{"&#32;", " "},  // space
		{"&#34;", "\""}, // double quote
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := htmlDecode([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("htmlDecode(%s) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHtmlDecode_MalformedEntities(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"&lt", "<"}, // without semicolon
		{"&gt", ">"},
		{"&quot", "\""},
		{"&apos", "'"},
		{"&amp", "&"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := htmlDecode([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("htmlDecode(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHtmlDecode_MixedContent(t *testing.T) {
	input := "Hello &lt;world&gt; &amp; universe"
	expected := "Hello <world> & universe"

	result := htmlDecode([]byte(input))
	if string(result) != expected {
		t.Errorf("htmlDecode(%s) = %s, want %s", input, result, expected)
	}
}

func TestHtmlDecode_NoEntities(t *testing.T) {
	input := "Plain text without entities"
	result := htmlDecode([]byte(input))

	if string(result) != input {
		t.Errorf("htmlDecode(%s) = %s, want %s", input, result, input)
	}
}

func TestBackslashUnescape_StandardEscapes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`\"`, `"`},
		{`\'`, `'`},
		{"\\`", "`"},
		{`\\`, `\`},
		{`\/`, `/`},
		{`\n`, "\n"},
		{`\r`, "\r"},
		{`\t`, "\t"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := backslashUnescape([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("backslashUnescape(%s) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBackslashUnescape_UnknownEscape(t *testing.T) {
	input := `\x`
	expected := `\x`

	result := backslashUnescape([]byte(input))
	if string(result) != expected {
		t.Errorf("backslashUnescape(%s) = %s, want %s", input, result, expected)
	}
}

func TestBackslashUnescape_MixedContent(t *testing.T) {
	input := `Hello \"world\" and \'universe\'`
	expected := `Hello "world" and 'universe'`

	result := backslashUnescape([]byte(input))
	if string(result) != expected {
		t.Errorf("backslashUnescape(%s) = %s, want %s", input, result, expected)
	}
}

func TestBackslashUnescape_NoEscapes(t *testing.T) {
	input := "Plain text without escapes"
	result := backslashUnescape([]byte(input))

	if string(result) != input {
		t.Errorf("backslashUnescape(%s) = %s, want %s", input, result, input)
	}
}

func TestBackslashUnescape_TrailingBackslash(t *testing.T) {
	input := `text\`
	result := backslashUnescape([]byte(input))

	// Should preserve trailing backslash (no character to escape)
	if string(result) != input {
		t.Errorf("backslashUnescape(%s) = %s, want %s", input, result, input)
	}
}

func TestExtractPresentChars_AllPresent(t *testing.T) {
	payload := GeneratePrimary()
	matchedBytes := []byte(payload.FullPayload)

	presentChars := ExtractPresentChars(matchedBytes, payload)

	for _, ch := range BreakoutChars {
		if !presentChars[ch] {
			t.Errorf("Char %c should be present", ch)
		}
	}
}

func TestExtractPresentChars_PartialPresent(t *testing.T) {
	payload := GeneratePrimary()

	// Remove some characters from the payload
	modified := strings.ReplaceAll(payload.FullPayload, "<", "")
	modified = strings.ReplaceAll(modified, ">", "")

	presentChars := ExtractPresentChars([]byte(modified), payload)

	// < and > should NOT be present
	if presentChars['<'] {
		t.Error("Char '<' should not be present")
	}
	if presentChars['>'] {
		t.Error("Char '>' should not be present")
	}
}

func TestExtractPresentChars_EmptyMatch(t *testing.T) {
	payload := GeneratePrimary()
	presentChars := ExtractPresentChars([]byte{}, payload)

	if len(presentChars) != 0 {
		t.Errorf("ExtractPresentChars on empty should return empty map")
	}
}

func TestCanaryMatch_Fields(t *testing.T) {
	match := &CanaryMatch{
		StartOffset:   10,
		EndOffset:     50,
		MatchedBytes:  []byte("test"),
		DetectionMode: MatchHTMLDecode,
	}

	if match.StartOffset != 10 {
		t.Errorf("StartOffset = %d, want 10", match.StartOffset)
	}
	if match.EndOffset != 50 {
		t.Errorf("EndOffset = %d, want 50", match.EndOffset)
	}
	if string(match.MatchedBytes) != "test" {
		t.Errorf("MatchedBytes = %s, want 'test'", match.MatchedBytes)
	}
	if match.DetectionMode != MatchHTMLDecode {
		t.Errorf("DetectionMode = %v, want MatchHTMLDecode", match.DetectionMode)
	}
}

func TestFindCanaryMatches_RemovesDuplicates(t *testing.T) {
	payload := GeneratePrimary()

	// Create body where different encoding modes might find same match
	body := []byte(payload.FullPayload)

	matches := FindCanaryMatches(body, payload)

	// Should have exactly 1 unique match (deduplicated by offset)
	if len(matches) != 1 {
		t.Errorf("FindCanaryMatches returned %d matches, want 1 (deduplicated)", len(matches))
	}
}

func TestFindCanaryMatches_SortedByOffset(t *testing.T) {
	payload := GeneratePrimary()
	body := []byte("A" + payload.FullPayload + "B" + payload.FullPayload + "C")

	matches := FindCanaryMatches(body, payload)

	for i := 1; i < len(matches); i++ {
		if matches[i].StartOffset <= matches[i-1].StartOffset {
			t.Errorf("Matches not sorted by offset: [%d].StartOffset=%d <= [%d].StartOffset=%d",
				i, matches[i].StartOffset, i-1, matches[i-1].StartOffset)
		}
	}
}

func TestDecodeNumericEntities_InvalidEntity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"&#;", "&#;"},                       // empty number
		{"&#abc;", "&#abc;"},                 // not a number
		{"&#99999999999;", "&#99999999999;"}, // too large (would fail parse)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := decodeNumericEntities(tt.input)
			if result != tt.expected {
				t.Errorf("decodeNumericEntities(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDecodeNumericEntities_Unicode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"&#128512;", "😀"}, // emoji (U+1F600)
		{"&#x1F600;", "😀"}, // emoji hex
		{"&#8364;", "€"},   // euro sign
		{"&#x20AC;", "€"},  // euro sign hex
		{"&#12354;", "あ"},  // hiragana
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := decodeNumericEntities(tt.input)
			if result != tt.expected {
				t.Errorf("decodeNumericEntities(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFindCanaryMatches_EmptyBody(t *testing.T) {
	payload := GeneratePrimary()
	matches := FindCanaryMatches([]byte{}, payload)

	if len(matches) != 0 {
		t.Errorf("FindCanaryMatches on empty body returned %d matches, want 0", len(matches))
	}
}

func TestFindCanaryMatches_PartialPayload(t *testing.T) {
	payload := GeneratePrimary()

	// Only include part of the payload
	partial := payload.FullPayload[:len(payload.FullPayload)/2]
	body := []byte(partial)

	matches := FindCanaryMatches(body, payload)

	if len(matches) != 0 {
		t.Errorf("FindCanaryMatches on partial payload returned %d matches, want 0", len(matches))
	}
}

func TestHtmlDecode_ComplexNumericEntities(t *testing.T) {
	// Test mix of decimal and hex
	input := "&#60;div&#x3e;"
	expected := "<div>"

	result := htmlDecode([]byte(input))
	if string(result) != expected {
		t.Errorf("htmlDecode(%s) = %s, want %s", input, result, expected)
	}
}

func TestBackslashUnescape_MultipleSequential(t *testing.T) {
	input := `\\\\` // 4 backslashes -> 2 backslashes
	expected := `\\`

	result := backslashUnescape([]byte(input))
	if string(result) != expected {
		t.Errorf("backslashUnescape(%s) = %s, want %s", input, result, expected)
	}
}

func TestExtractPresentChars_EncodedChars(t *testing.T) {
	// When chars are encoded, they should still be detected
	// because the matcher decodes before comparing
	payload := GeneratePrimary()

	// This test verifies the function works with decoded bytes
	// The actual matching with encoding is done by FindCanaryMatches
	matchedBytes := []byte(payload.FullPayload)
	presentChars := ExtractPresentChars(matchedBytes, payload)

	// All primary chars should be present
	if len(presentChars) != len(BreakoutChars) {
		t.Errorf("ExtractPresentChars found %d chars, want %d", len(presentChars), len(BreakoutChars))
	}
}

// TestFindCanaryMatches_BackslashEscapeCorrectOffset verifies the bug fix for p15 scenario
// where backslash-escaped matches should have correct offset and matchedBytes from original response
func TestFindCanaryMatches_BackslashEscapeCorrectOffset(t *testing.T) {
	payload := GeneratePrimary()

	// Simulate p15 response: var p15 = 'rza3\'obel"dkdd`ahp3&lt;mwf8>c0wg jc25=xx6e/eu84';
	// Where ' is escaped to \'
	escaped := strings.ReplaceAll(payload.FullPayload, "'", "\\'")
	body := []byte("var p15 = '" + escaped + "';")

	matches := FindCanaryMatches(body, payload)

	if len(matches) == 0 {
		t.Fatal("FindCanaryMatches should find backslash-escaped payload")
	}

	// Find the match detected via backslash unescape mode
	var backslashMatch *CanaryMatch
	for _, m := range matches {
		if m.DetectionMode == MatchBackslashUnescape {
			backslashMatch = m
			break
		}
	}

	if backslashMatch == nil {
		t.Fatal("Should have a match via MatchBackslashUnescape mode")
	}

	// CRITICAL: matchedBytes should contain the escaped sequence \'
	// NOT the unescaped version
	matchStr := string(backslashMatch.MatchedBytes)
	if !strings.Contains(matchStr, "\\'") {
		t.Errorf("matchedBytes should contain escaped \\' but got: %q", matchStr)
	}

	// Verify offset points to correct position in original body
	expectedPrefix := "var p15 = '"
	if backslashMatch.StartOffset != len(expectedPrefix) {
		t.Errorf("StartOffset = %d, want %d (after '%s')", backslashMatch.StartOffset, len(expectedPrefix), expectedPrefix)
	}

	// Verify extracting bytes from original body at this offset matches matchedBytes
	extractedFromBody := body[backslashMatch.StartOffset:backslashMatch.EndOffset]
	if string(extractedFromBody) != matchStr {
		t.Errorf("Body[%d:%d] = %q, want %q",
			backslashMatch.StartOffset, backslashMatch.EndOffset, extractedFromBody, matchStr)
	}
}

// TestFindCanaryMatches_HTMLEncodedCorrectOffset verifies HTML encoded matches have correct offset
func TestFindCanaryMatches_HTMLEncodedCorrectOffset(t *testing.T) {
	payload := GeneratePrimary()

	// HTML encode < and >
	encoded := strings.ReplaceAll(payload.FullPayload, "<", "&lt;")
	encoded = strings.ReplaceAll(encoded, ">", "&gt;")
	body := []byte("prefix" + encoded + "suffix")

	matches := FindCanaryMatches(body, payload)

	if len(matches) == 0 {
		t.Fatal("FindCanaryMatches should find HTML-encoded payload")
	}

	// Find HTML decode match
	var htmlMatch *CanaryMatch
	for _, m := range matches {
		if m.DetectionMode == MatchHTMLDecode {
			htmlMatch = m
			break
		}
	}

	if htmlMatch == nil {
		t.Fatal("Should have a match via MatchHTMLDecode mode")
	}

	// matchedBytes should contain the encoded entities &lt; and &gt;
	matchStr := string(htmlMatch.MatchedBytes)
	if !strings.Contains(matchStr, "&lt;") || !strings.Contains(matchStr, "&gt;") {
		t.Errorf("matchedBytes should contain &lt; and &gt; but got: %q", matchStr)
	}

	// Verify offset
	if htmlMatch.StartOffset != 6 { // len("prefix")
		t.Errorf("StartOffset = %d, want 6", htmlMatch.StartOffset)
	}
}

// TestMapToOriginalOffset verifies offset mapping from transformed to original
func TestMapToOriginalOffset(t *testing.T) {
	tests := []struct {
		name              string
		original          string
		transformedOffset int
		mode              MatchMode
		expectedOffset    int
	}{
		{
			name:              "backslash_escape_single",
			original:          `hello\'world`,
			transformedOffset: 6, // position of 'w' in "hello'world"
			mode:              MatchBackslashUnescape,
			expectedOffset:    7, // position of 'w' in original (after \')
		},
		{
			name:              "backslash_escape_multiple",
			original:          `a\'b\"c`,
			transformedOffset: 3, // position of '"' in "a'b"c" (after unescape)
			mode:              MatchBackslashUnescape,
			expectedOffset:    4, // position of '\"' in original: a(0) \'(1-2) b(3) \"(4-5) c(6)
		},
		{
			name:              "html_entity_lt",
			original:          "a&lt;b",
			transformedOffset: 2, // position of 'b' in "a<b"
			mode:              MatchHTMLDecode,
			expectedOffset:    5, // position of 'b' in original (after &lt;)
		},
		{
			name:              "html_entity_multiple",
			original:          "&lt;&gt;x",
			transformedOffset: 2, // position of 'x' in "<>x"
			mode:              MatchHTMLDecode,
			expectedOffset:    8, // position of 'x' in original
		},
		{
			name:              "no_transform",
			original:          "hello",
			transformedOffset: 3,
			mode:              MatchSimple,
			expectedOffset:    3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapToOriginalOffset([]byte(tt.original), tt.transformedOffset, tt.mode)
			if result != tt.expectedOffset {
				t.Errorf("mapToOriginalOffset(%q, %d, %v) = %d, want %d",
					tt.original, tt.transformedOffset, tt.mode, result, tt.expectedOffset)
			}
		})
	}
}

// TestFindMatchEndInOriginal verifies end offset calculation
func TestFindMatchEndInOriginal(t *testing.T) {
	tests := []struct {
		name        string
		original    string
		startOffset int
		patternLen  int
		mode        MatchMode
		expectedEnd int
	}{
		{
			name:        "backslash_escape",
			original:    `\'hello`,
			startOffset: 0,
			patternLen:  6, // "'hello" after unescape
			mode:        MatchBackslashUnescape,
			expectedEnd: 7, // "\\'hello" in original
		},
		{
			name:        "html_entity",
			original:    "&lt;div",
			startOffset: 0,
			patternLen:  4, // "<div" after decode
			mode:        MatchHTMLDecode,
			expectedEnd: 7, // "&lt;div" in original
		},
		{
			name:        "mixed_backslash",
			original:    `a\'b\"c`,
			startOffset: 0,
			patternLen:  5, // "a'b\"c" after unescape
			mode:        MatchBackslashUnescape,
			expectedEnd: 7, // full string in original
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findMatchEndInOriginal([]byte(tt.original), tt.startOffset, tt.patternLen, tt.mode)
			if result != tt.expectedEnd {
				t.Errorf("findMatchEndInOriginal(%q, %d, %d, %v) = %d, want %d",
					tt.original, tt.startOffset, tt.patternLen, tt.mode, result, tt.expectedEnd)
			}
		})
	}
}

// TestFindEntityLength verifies HTML entity length detection
func TestFindEntityLength(t *testing.T) {
	tests := []struct {
		input    string
		offset   int
		expected int
	}{
		{"&lt;", 0, 4},
		{"&gt;", 0, 4},
		{"&amp;", 0, 5},
		{"&quot;", 0, 6},
		{"&apos;", 0, 6},
		{"&grave;", 0, 7},
		{"&#39;", 0, 5},
		{"&#x27;", 0, 6},
		{"x&lt;y", 1, 4},
		{"not entity", 0, 0},
		{"&unknown;", 0, 0}, // not a known entity
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := findEntityLength([]byte(tt.input), tt.offset)
			if result != tt.expected {
				t.Errorf("findEntityLength(%q, %d) = %d, want %d", tt.input, tt.offset, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkFindCanaryMatches(b *testing.B) {
	payload := GeneratePrimary()
	body := []byte(strings.Repeat("x", 10000) + payload.FullPayload + strings.Repeat("y", 10000))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FindCanaryMatches(body, payload)
	}
}

func BenchmarkHtmlDecode(b *testing.B) {
	input := []byte("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		htmlDecode(input)
	}
}

func BenchmarkBackslashUnescape(b *testing.B) {
	input := []byte(`Hello \"world\" and \'universe\' with \\backslash\\`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		backslashUnescape(input)
	}
}
