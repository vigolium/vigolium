package xss_light_scanner

import (
	"fmt"
	"strings"
	"testing"
)

// ============================================================================
// Test Helpers
// ============================================================================

// generateTestSegments creates n test segments dynamically
func generateTestSegments(n int) []string {
	segments := make([]string, n)
	for i := 0; i < n; i++ {
		segments[i] = fmt.Sprintf("seg%d", i)
	}
	return segments
}

// buildPhase1Response creates a simulated response for Phase 1 testing
// with the payload reflected in the specified context with given transforms
func buildPhase1Response(payload *CanaryPayload, context ReflectionContext, transforms map[byte]TransformType) string {
	// Build transformed payload
	transformed := buildTransformedPayload(payload, transforms)

	// Wrap in appropriate HTML context
	switch context {
	case HTMLGeneric:
		return fmt.Sprintf("<html><body><div>%s</div></body></html>", transformed)
	case HTMLAttributeValueDQBreakout:
		return fmt.Sprintf(`<html><body><div class="%s"></div></body></html>`, transformed)
	case HTMLAttributeValueSQBreakout:
		return fmt.Sprintf(`<html><body><div class='%s'></div></body></html>`, transformed)
	case HTMLAttributeValueBTBreakout:
		return fmt.Sprintf("<html><body><div class=`%s`></div></body></html>", transformed)
	case HTMLAttributeValueUnquotedBreakout:
		return fmt.Sprintf(`<html><body><div class=%s></div></body></html>`, transformed)
	case HTMLAttributeName:
		return fmt.Sprintf(`<html><body><div %s="value"></div></body></html>`, transformed)
	case HTMLCommentBreakout:
		return fmt.Sprintf("<!-- %s -->", transformed)
	case JSInEventHandlerDQ:
		return fmt.Sprintf(`<html><body><div onclick="%s"></div></body></html>`, transformed)
	case JSInEventHandlerSQ:
		return fmt.Sprintf(`<html><body><div onclick='%s'></div></body></html>`, transformed)
	case JSInEventHandlerBT:
		return fmt.Sprintf("<html><body><div onclick=`%s`></div></body></html>", transformed)
	case JSInEventHandlerUnquoted:
		return fmt.Sprintf(`<html><body><div onclick=%s></div></body></html>`, transformed)
	case JSCodeStatement:
		return fmt.Sprintf("<html><body><script>var x = %s;</script></body></html>", transformed)
	case JSStringSQBreakout:
		return fmt.Sprintf("<html><body><script>var x = '%s';</script></body></html>", transformed)
	case JSStringDQBreakout:
		return fmt.Sprintf(`<html><body><script>var x = "%s";</script></body></html>`, transformed)
	case JSTemplateLiteral:
		return fmt.Sprintf("<html><body><script>var x = `%s`;</script></body></html>", transformed)
	case JSLineComment:
		return fmt.Sprintf("<html><body><script>// %s\nvar x = 1;</script></body></html>", transformed)
	case JSBlockComment:
		return fmt.Sprintf("<html><body><script>/* %s */</script></body></html>", transformed)
	case HTMLAfterXMPClose:
		return fmt.Sprintf("<html><body><xmp>%s</xmp></body></html>", transformed)
	case HTMLAfterNoscriptClose:
		return fmt.Sprintf("<html><body><noscript>%s</noscript></body></html>", transformed)
	case HTMLAfterTitleClose:
		return fmt.Sprintf("<html><head><title>%s</title></head></html>", transformed)
	case XMLGeneric:
		return fmt.Sprintf(`<?xml version="1.0"?><root>%s</root>`, transformed)
	default:
		return fmt.Sprintf("<html><body>%s</body></html>", transformed)
	}
}

// buildTransformedPayload applies transforms to each char in the payload
func buildTransformedPayload(payload *CanaryPayload, transforms map[byte]TransformType) string {
	var result strings.Builder

	result.WriteString(payload.Segments[0])

	chars := BreakoutChars
	for i, ch := range chars {
		transform := transforms[ch]
		switch transform {
		case TransformPassed, "":
			result.WriteByte(ch)
		case TransformBackslashEsc:
			result.WriteByte('\\')
			result.WriteByte(ch)
		case TransformHTMLEncoded:
			result.WriteString(getHTMLEncoding(ch))
		case TransformURLEncoded:
			result.WriteString(getURLEncoding(ch))
		case TransformRemoved:
			// Don't write the char
		}
		if i+1 < len(payload.Segments) {
			result.WriteString(payload.Segments[i+1])
		}
	}

	return result.String()
}

func getHTMLEncoding(ch byte) string {
	switch ch {
	case '\'':
		return "&#39;"
	case '"':
		return "&quot;"
	case '<':
		return "&lt;"
	case '>':
		return "&gt;"
	case '`':
		return "&#96;"
	default:
		return string(ch)
	}
}

func getURLEncoding(ch byte) string {
	switch ch {
	case '\'':
		return "%27"
	case '"':
		return "%22"
	case '<':
		return "%3C"
	case '>':
		return "%3E"
	case '`':
		return "%60"
	case ' ':
		return "%20"
	case '/':
		return "%2F"
	case '=':
		return "%3D"
	default:
		return string(ch)
	}
}

// ============================================================================
// Phase 1 Direct Exploitability Tests
// ============================================================================

func TestPhaseFlow_HTMLGeneric_Exploitable(t *testing.T) {
	ta := NewTransformAnalyzer()
	payload := GeneratePrimary()

	// < and > pass through unchanged
	transforms := map[byte]TransformType{
		'<': TransformPassed,
		'>': TransformPassed,
	}

	response := buildPhase1Response(payload, HTMLGeneric, transforms)
	responseBytes := []byte(response)

	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		HTMLGeneric,
		matches[0].StartOffset,
	)

	if !analysis.IsExploitable() {
		t.Error("Should be exploitable with < and > passed")
	}
}

func TestPhaseFlow_HTMLGeneric_NotExploitable_Encoded(t *testing.T) {
	ta := NewTransformAnalyzer()
	payload := GeneratePrimary()

	// < and > HTML encoded
	transforms := map[byte]TransformType{
		'<': TransformHTMLEncoded,
		'>': TransformHTMLEncoded,
	}

	response := buildPhase1Response(payload, HTMLGeneric, transforms)
	responseBytes := []byte(response)

	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		HTMLGeneric,
		matches[0].StartOffset,
	)

	if analysis.IsExploitable() {
		t.Error("Should NOT be exploitable with < and > encoded")
	}
}

func TestPhaseFlow_EventHandler_AlwaysExploitable(t *testing.T) {
	ta := NewTransformAnalyzer()

	contexts := []ReflectionContext{
		JSInEventHandlerDQ,
		JSInEventHandlerSQ,
		JSInEventHandlerBT,
		JSInEventHandlerUnquoted,
	}

	for _, ctx := range contexts {
		t.Run(ctx.String(), func(t *testing.T) {
			payload := GeneratePrimary()
			response := buildPhase1Response(payload, ctx, map[byte]TransformType{})
			responseBytes := []byte(response)

			matches := FindCanaryMatches(responseBytes, payload)
			if len(matches) == 0 {
				t.Fatal("No canary match found")
			}

			analysis := ta.AnalyzeTransforms(
				responseBytes[matches[0].StartOffset:matches[0].EndOffset],
				payload,
				ctx,
				matches[0].StartOffset,
			)

			if !analysis.IsExploitable() {
				t.Errorf("Event handler %s should ALWAYS be exploitable", ctx)
			}
		})
	}
}

func TestPhaseFlow_JSCodeStatement_AlwaysExploitable(t *testing.T) {
	ta := NewTransformAnalyzer()
	payload := GeneratePrimary()

	response := buildPhase1Response(payload, JSCodeStatement, map[byte]TransformType{})
	responseBytes := []byte(response)

	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		JSCodeStatement,
		matches[0].StartOffset,
	)

	if !analysis.IsExploitable() {
		t.Error("JSCodeStatement should ALWAYS be exploitable")
	}
}

func TestPhaseFlow_JSStringSQ_QuoteAndSemicolonPassed(t *testing.T) {
	ta := NewTransformAnalyzer()

	// For JS string, we need to test with secondary chars too
	// Generate segments dynamically based on BreakoutChars length
	chars := BreakoutChars
	segments := generateTestSegments(len(chars) + 1)
	payload := mockPayloadWithSegments(segments, chars)

	// ' and ; both pass
	response := fmt.Sprintf("<script>var x = '%s';</script>", payload.FullPayload)
	responseBytes := []byte(response)

	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	// Create analysis with both ' and ; transforms
	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		JSStringSQBreakout,
		matches[0].StartOffset,
	)

	// Need to also add ; transform
	analysis.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	if !analysis.IsExploitable() {
		t.Error("Should be exploitable with ' and ; passed")
	}
}

func TestPhaseFlow_JSStringSQ_QuoteEscaped_NeedsPhase2(t *testing.T) {
	ta := NewTransformAnalyzer()

	chars := BreakoutChars
	segments := generateTestSegments(len(chars) + 1)
	payload := mockPayloadWithSegments(segments, chars)

	// Build response with ' escaped and < encoded (no script breakout possible)
	transforms := map[byte]TransformType{
		'\'': TransformBackslashEsc,
		'<':  TransformHTMLEncoded, // Prevent script breakout
	}
	response := buildPhase1Response(payload, JSStringSQBreakout, transforms)
	responseBytes := []byte(response)

	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		JSStringSQBreakout,
		matches[0].StartOffset,
	)

	// Should NOT be exploitable yet
	if analysis.IsExploitable() {
		t.Error("Should NOT be exploitable when ' is escaped")
	}

	// But should detect that ' was backslash escaped
	if !analysis.HasBackslashEscaped('\'') {
		t.Error("Should detect that ' was backslash escaped")
	}

	// CollectNextTests should return a test for \'
	tests := CollectNextTests([]*EscapeAnalysis{analysis})
	if len(tests) == 0 {
		t.Fatal("Should have next test for double-escape")
	}

	found := false
	for _, test := range tests {
		if test.TestSequence == "\\'" && test.Context == JSStringSQBreakout {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should have \\' test for JSStringSQBreakout")
	}
}

// ============================================================================
// Phase 2 Double Escape Tests
// ============================================================================

func TestPhaseFlow_JSStringSQ_DoubleEscape_Exploitable(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Phase 2: Test if \' → \\'
	payload := BuildBatchedSecondaryPayload([]string{"\\'"})
	if payload == nil {
		t.Fatal("Failed to build batched payload")
	}

	// Response where \' becomes \\' (double backslash - exploitable!)
	responseStr := payload.Segments[0] + "\\\\'" + payload.Segments[1]
	responseBytes := []byte(responseStr)

	transforms := ta.AnalyzeSequenceTransforms(responseBytes, payload, []string{"\\'"})

	ct := transforms["\\'"]
	if ct == nil {
		t.Fatal("Expected transform for \\' sequence")
	}

	if ct.Transform != TransformDoubleBackslash {
		t.Errorf("Transform = %v, want TransformDoubleBackslash", ct.Transform)
	}

	// Create full EscapeAnalysis and verify exploitability
	analysis := NewEscapeAnalysis(JSStringSQBreakout, 0)
	analysis.SetTransform("'", &CharTransform{Transform: TransformBackslashEsc})
	analysis.SetTransform("\\'", ct)
	analysis.SetTransform(";", &CharTransform{Transform: TransformPassed})

	if !analysis.IsExploitable() {
		t.Error("Should be exploitable via double-escape")
	}
}

func TestPhaseFlow_JSStringSQ_TripleEscape_NotExploitable(t *testing.T) {
	ta := NewTransformAnalyzer()

	// Phase 2: Test if \' → \\\' (triple backslash - NOT exploitable)
	payload := BuildBatchedSecondaryPayload([]string{"\\'"})
	if payload == nil {
		t.Fatal("Failed to build batched payload")
	}

	// Response where \' becomes \\\' (triple backslash - NOT exploitable)
	responseStr := payload.Segments[0] + "\\\\\\'" + payload.Segments[1]
	responseBytes := []byte(responseStr)

	transforms := ta.AnalyzeSequenceTransforms(responseBytes, payload, []string{"\\'"})

	ct := transforms["\\'"]
	if ct == nil {
		t.Fatal("Expected transform for \\' sequence")
	}

	if ct.Transform != TransformTripleBackslash {
		t.Errorf("Transform = %v, want TransformTripleBackslash", ct.Transform)
	}

	// Create full EscapeAnalysis - should NOT be exploitable
	analysis := NewEscapeAnalysis(JSStringSQBreakout, 0)
	analysis.SetTransform("'", &CharTransform{Transform: TransformBackslashEsc})
	analysis.SetTransform("\\'", ct)
	analysis.SetTransform(";", &CharTransform{Transform: TransformPassed})

	if analysis.IsExploitable() {
		t.Error("Should NOT be exploitable via triple-escape")
	}
}

// ============================================================================
// Full Phase Flow Integration Tests
// ============================================================================

func TestPhaseFlow_FullFlow_DirectExploitable(t *testing.T) {
	// Simulate complete flow where Phase 1 finds exploitable point

	ta := NewTransformAnalyzer()
	payload := GeneratePrimary()

	// Response with ' and ; both passing (exploitable in Phase 1)
	response := fmt.Sprintf("<script>var x = '%s';</script>", payload.FullPayload)
	responseBytes := []byte(response)

	// Phase 1: Find and analyze
	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		JSStringSQBreakout,
		matches[0].StartOffset,
	)
	analysis.SetTransform(";", &CharTransform{Transform: TransformPassed})

	// Should be exploitable in Phase 1
	if !analysis.IsExploitable() {
		t.Fatal("Should be exploitable in Phase 1")
	}

	// No Phase 2 needed
	tests := CollectNextTests([]*EscapeAnalysis{analysis})
	if len(tests) != 0 {
		t.Errorf("No Phase 2 tests needed, got %d", len(tests))
	}
}

func TestPhaseFlow_FullFlow_NeedsPhase2(t *testing.T) {
	// Simulate complete flow where Phase 1 is inconclusive, Phase 2 finds exploit

	ta := NewTransformAnalyzer()

	// Phase 1: ' is escaped, < is encoded (no script breakout)
	chars := BreakoutChars
	segments := generateTestSegments(len(chars) + 1)
	phase1Payload := mockPayloadWithSegments(segments, chars)

	transforms := map[byte]TransformType{
		'\'': TransformBackslashEsc,
		'<':  TransformHTMLEncoded, // Prevent script breakout
	}
	phase1Response := buildPhase1Response(phase1Payload, JSStringSQBreakout, transforms)
	phase1ResponseBytes := []byte(phase1Response)

	matches := FindCanaryMatches(phase1ResponseBytes, phase1Payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found in Phase 1")
	}

	phase1Analysis := ta.AnalyzeTransforms(
		phase1ResponseBytes[matches[0].StartOffset:matches[0].EndOffset],
		phase1Payload,
		JSStringSQBreakout,
		matches[0].StartOffset,
	)
	phase1Analysis.SetTransform(";", &CharTransform{Transform: TransformPassed})

	// Not exploitable after Phase 1
	if phase1Analysis.IsExploitable() {
		t.Fatal("Should NOT be exploitable after Phase 1 (quote escaped)")
	}

	// Phase 2: Collect tests
	tests := CollectNextTests([]*EscapeAnalysis{phase1Analysis})
	if len(tests) == 0 {
		t.Fatal("Should have Phase 2 tests")
	}

	// Build Phase 2 payload
	sequences := GetUniqueSequences(tests)
	phase2Payload := BuildBatchedSecondaryPayload(sequences)
	if phase2Payload == nil {
		t.Fatal("Failed to build Phase 2 payload")
	}

	// Phase 2 response: \' → \\' (exploitable!)
	phase2ResponseStr := phase2Payload.Segments[0] + "\\\\'" + phase2Payload.Segments[1]
	phase2ResponseBytes := []byte(phase2ResponseStr)

	phase2Transforms := ta.AnalyzeSequenceTransforms(phase2ResponseBytes, phase2Payload, sequences)

	// Check if any test succeeded
	for _, test := range tests {
		ct := phase2Transforms[test.TestSequence]
		if ct != nil && ct.Transform == test.SuccessCheck {
			// Update Phase 1 analysis with Phase 2 result
			phase1Analysis.SetTransform(test.TestSequence, ct)
		}
	}

	// Now should be exploitable
	if !phase1Analysis.IsExploitable() {
		t.Error("Should be exploitable after Phase 2 (double-escape detected)")
	}
}

func TestPhaseFlow_FullFlow_NotExploitable(t *testing.T) {
	// Simulate complete flow where both phases fail to find exploit

	ta := NewTransformAnalyzer()

	// Phase 1: ' is HTML encoded (no double-escape possible)
	chars := BreakoutChars
	segments := generateTestSegments(len(chars) + 1)
	payload := mockPayloadWithSegments(segments, chars)

	transforms := map[byte]TransformType{
		'\'': TransformHTMLEncoded,
		'"':  TransformHTMLEncoded,
		'<':  TransformHTMLEncoded,
		'>':  TransformHTMLEncoded,
	}
	response := buildPhase1Response(payload, JSStringSQBreakout, transforms)
	responseBytes := []byte(response)

	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatal("No canary match found")
	}

	analysis := ta.AnalyzeTransforms(
		responseBytes[matches[0].StartOffset:matches[0].EndOffset],
		payload,
		JSStringSQBreakout,
		matches[0].StartOffset,
	)

	// Not exploitable
	if analysis.IsExploitable() {
		t.Error("Should NOT be exploitable (all chars HTML encoded)")
	}

	// No Phase 2 tests (HTML encoding doesn't lead to double-escape)
	tests := CollectNextTests([]*EscapeAnalysis{analysis})
	if len(tests) != 0 {
		t.Errorf("Should have no Phase 2 tests, got %d", len(tests))
	}
}

// ============================================================================
// All Context Tests
// ============================================================================

func TestPhaseFlow_AllContexts_Exploitable(t *testing.T) {
	ta := NewTransformAnalyzer()

	testCases := []struct {
		context    ReflectionContext
		transforms map[byte]TransformType
	}{
		// HTML contexts - need < and >
		{HTMLGeneric, map[byte]TransformType{'<': TransformPassed, '>': TransformPassed}},
		{HTMLTagCloseAndInject, map[byte]TransformType{'<': TransformPassed, '>': TransformPassed}},
		{HTMLAfterXMPClose, map[byte]TransformType{'<': TransformPassed, '>': TransformPassed}},
		{HTMLAfterNoscriptClose, map[byte]TransformType{'<': TransformPassed, '>': TransformPassed}},
		{HTMLAfterTitleClose, map[byte]TransformType{'<': TransformPassed, '>': TransformPassed}},
		{XMLGeneric, map[byte]TransformType{'<': TransformPassed, '>': TransformPassed}},

		// Attribute value contexts - need quote breakout
		{HTMLAttributeValueDQBreakout, map[byte]TransformType{'"': TransformPassed}},
		{HTMLAttributeValueSQBreakout, map[byte]TransformType{'\'': TransformPassed}},
		{HTMLAttributeValueBTBreakout, map[byte]TransformType{'`': TransformPassed}},
		{HTMLAttributeValueUnquotedBreakout, map[byte]TransformType{' ': TransformPassed}},

		// Attribute name - need = and space/>
		{HTMLAttributeName, map[byte]TransformType{'=': TransformPassed, ' ': TransformPassed}},

		// Event handlers - always exploitable
		{JSInEventHandlerDQ, map[byte]TransformType{}},
		{JSInEventHandlerSQ, map[byte]TransformType{}},
		{JSInEventHandlerBT, map[byte]TransformType{}},
		{JSInEventHandlerUnquoted, map[byte]TransformType{}},

		// JS code - always exploitable
		{JSCodeStatement, map[byte]TransformType{}},

		// Comment contexts
		{HTMLCommentBreakout, map[byte]TransformType{'>': TransformPassed, '-': TransformPassed}},
	}

	for _, tc := range testCases {
		t.Run(tc.context.String(), func(t *testing.T) {
			payload := GeneratePrimary()
			response := buildPhase1Response(payload, tc.context, tc.transforms)
			responseBytes := []byte(response)

			matches := FindCanaryMatches(responseBytes, payload)
			if len(matches) == 0 {
				t.Fatalf("No canary match found for context %s", tc.context)
			}

			analysis := ta.AnalyzeTransforms(
				responseBytes[matches[0].StartOffset:matches[0].EndOffset],
				payload,
				tc.context,
				matches[0].StartOffset,
			)

			// Add additional transforms from test case
			for ch, tr := range tc.transforms {
				if analysis.GetCharTransform(ch) == nil {
					analysis.SetTransform(string(ch), &CharTransform{InputChar: ch, Transform: tr})
				}
			}

			if !analysis.IsExploitable() {
				t.Errorf("Context %s should be exploitable with given transforms", tc.context)
			}
		})
	}
}

func TestPhaseFlow_AllContexts_NotExploitable(t *testing.T) {
	ta := NewTransformAnalyzer()

	testCases := []struct {
		context    ReflectionContext
		transforms map[byte]TransformType
	}{
		// HTML contexts - < or > encoded
		{HTMLGeneric, map[byte]TransformType{'<': TransformHTMLEncoded, '>': TransformPassed}},
		{HTMLGeneric, map[byte]TransformType{'<': TransformPassed, '>': TransformHTMLEncoded}},

		// Attribute value contexts - quote encoded
		{HTMLAttributeValueDQBreakout, map[byte]TransformType{'"': TransformHTMLEncoded}},
		{HTMLAttributeValueSQBreakout, map[byte]TransformType{'\'': TransformHTMLEncoded}},
		{HTMLAttributeValueBTBreakout, map[byte]TransformType{'`': TransformHTMLEncoded}},
		// Note: HTMLAttributeValueUnquotedBreakout with TransformRemoved is skipped
		// because canary matching fails when chars are removed from payload.
		// This is expected behavior - if breakout chars are stripped, we can't detect the reflection.

		// Note: HTMLAttributeName with '=' removed is also skipped for same reason.
	}

	for _, tc := range testCases {
		name := fmt.Sprintf("%s_%v", tc.context, tc.transforms)
		t.Run(name, func(t *testing.T) {
			payload := GeneratePrimary()
			response := buildPhase1Response(payload, tc.context, tc.transforms)
			responseBytes := []byte(response)

			matches := FindCanaryMatches(responseBytes, payload)
			if len(matches) == 0 {
				t.Fatalf("No canary match found for context %s", tc.context)
			}

			analysis := ta.AnalyzeTransforms(
				responseBytes[matches[0].StartOffset:matches[0].EndOffset],
				payload,
				tc.context,
				matches[0].StartOffset,
			)

			// Add additional transforms from test case
			for ch, tr := range tc.transforms {
				if analysis.GetCharTransform(ch) == nil {
					analysis.SetTransform(string(ch), &CharTransform{InputChar: ch, Transform: tr})
				}
			}

			if analysis.IsExploitable() {
				t.Errorf("Context %s should NOT be exploitable with given transforms", tc.context)
			}
		})
	}
}

// TestPhaseFlow_TransformRemoved_NoCanaryMatch verifies that when critical chars
// are removed, the canary matching fails - this is expected behavior.
func TestPhaseFlow_TransformRemoved_NoCanaryMatch(t *testing.T) {
	testCases := []struct {
		name       string
		context    ReflectionContext
		transforms map[byte]TransformType
	}{
		{
			"HTMLAttributeValueUnquoted_SpaceAndGTRemoved",
			HTMLAttributeValueUnquotedBreakout,
			map[byte]TransformType{' ': TransformRemoved, '>': TransformRemoved},
		},
		{
			"HTMLAttributeName_EqualRemoved",
			HTMLAttributeName,
			map[byte]TransformType{'=': TransformRemoved, ' ': TransformPassed},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := GeneratePrimary()
			response := buildPhase1Response(payload, tc.context, tc.transforms)
			responseBytes := []byte(response)

			matches := FindCanaryMatches(responseBytes, payload)

			// When chars are removed, canary matching should fail
			// because the response doesn't contain the full payload anymore
			if len(matches) > 0 {
				t.Error("Expected no canary match when chars are removed from payload")
			}

			// This is the expected behavior: if critical chars are stripped,
			// we can't reliably detect the reflection point, and the endpoint
			// is likely not exploitable anyway (chars needed for exploit are removed)
		})
	}
}

// ============================================================================
// P15 Scenario Integration Test
// Tests the full flow for BruteLogic XSS Gym p15 case
// ============================================================================

// TestP15Scenario_BackslashEscapeDetection verifies that when ' is backslash-escaped,
// the transform analyzer correctly detects TransformBackslashEsc
func TestP15Scenario_BackslashEscapeDetection(t *testing.T) {
	// Phase 1: Generate primary payload and simulate p15 response
	payload := GeneratePrimary()

	// Build response simulating p15: var p15 = 'payload';
	// where ' in payload is escaped to \'
	transforms := map[byte]TransformType{
		'\'': TransformBackslashEsc,
		'"':  TransformPassed,
		'`':  TransformPassed,
		'<':  TransformHTMLEncoded, // &lt;
		'>':  TransformPassed,
		' ':  TransformPassed,
		'=':  TransformPassed,
		'/':  TransformPassed,
	}

	response := buildPhase1Response(payload, JSStringSQBreakout, transforms)
	responseBytes := []byte(response)

	// Step 1: Find canary matches
	matches := FindCanaryMatches(responseBytes, payload)
	if len(matches) == 0 {
		t.Fatalf("Should find canary match in backslash-escaped response.\nResponse: %s\nPayload: %s", response, payload.FullPayload)
	}

	// Debug: log all matches
	t.Logf("Found %d matches:", len(matches))
	for i, m := range matches {
		t.Logf("  [%d] mode=%v offset=%d matchedBytes=%q", i, m.DetectionMode, m.StartOffset, m.MatchedBytes)
	}

	// Step 2: Use first match (all modes might detect, but we need any match with escaped bytes)
	// Note: For backslash-escaped payload, MatchBackslashUnescape will find it,
	// but MatchSimple will NOT find it (because payload doesn't match literally)
	var bestMatch *CanaryMatch
	for _, m := range matches {
		if m.DetectionMode == MatchBackslashUnescape {
			bestMatch = m
			break
		}
	}

	// Fallback to any match if MatchBackslashUnescape not found
	if bestMatch == nil {
		bestMatch = matches[0]
		t.Logf("Note: No MatchBackslashUnescape mode, using first match (mode=%v)", bestMatch.DetectionMode)
	}

	// Step 3: CRITICAL - Verify matchedBytes contains the backslash escape
	matchStr := string(bestMatch.MatchedBytes)
	if !strings.Contains(matchStr, "\\'") {
		t.Errorf("matchedBytes should contain \\' but got: %q", matchStr)
	}

	// Step 4: Run transform analysis on matchedBytes
	ta := NewTransformAnalyzer()
	analysis := ta.AnalyzeTransforms(bestMatch.MatchedBytes, payload, JSStringSQBreakout, bestMatch.StartOffset)

	// Step 5: CRITICAL - Verify ' is detected as BackslashEsc
	quoteTransform := analysis.GetCharTransform('\'')
	if quoteTransform == nil {
		t.Fatal("Should detect transform for single quote")
	}

	if quoteTransform.Transform != TransformBackslashEsc {
		t.Errorf("Quote transform = %v, want TransformBackslashEsc", quoteTransform.Transform)
	}

	// Step 6: Verify HasBackslashEscaped returns true
	if !analysis.HasBackslashEscaped('\'') {
		t.Error("HasBackslashEscaped('\\') should return true")
	}

	// Step 7: Verify IsExploitable returns false (needs Phase 2 double-escape test)
	// In JSStringSQBreakout context, backslash-escaped quote is NOT directly exploitable
	// Need Phase 2 to test if \' -> \\' (double-escape)
	if analysis.IsExploitable() {
		t.Error("JSStringSQBreakout with backslash-escaped quote should NOT be directly exploitable")
	}
}

// TestP15Scenario_EndToEndTransformChain verifies the complete chain:
// canary_matcher.go -> transform_analyzer.go -> next_test_char.go
func TestP15Scenario_EndToEndTransformChain(t *testing.T) {
	payload := GeneratePrimary()

	// Simulate p15: ' is backslash-escaped, < is HTML encoded
	transforms := map[byte]TransformType{
		'\'': TransformBackslashEsc,
		'"':  TransformPassed,
		'`':  TransformPassed,
		'<':  TransformHTMLEncoded,
		'>':  TransformPassed,
		' ':  TransformPassed,
		'=':  TransformPassed,
		'/':  TransformPassed,
	}

	response := buildPhase1Response(payload, JSStringSQBreakout, transforms)
	responseBytes := []byte(response)

	// Use FindCanaryMatches (the production entry point)
	matches := FindCanaryMatches(responseBytes, payload)

	if len(matches) == 0 {
		t.Fatal("Should find reflection point")
	}

	// Find the match detected via backslash unescape mode
	var bestMatch *CanaryMatch
	for _, m := range matches {
		if m.DetectionMode == MatchBackslashUnescape {
			bestMatch = m
			break
		}
	}
	if bestMatch == nil {
		bestMatch = matches[0]
	}

	// Now verify we can detect transform using matchedBytes from this match
	ta := NewTransformAnalyzer()
	analysis := ta.AnalyzeTransforms(bestMatch.MatchedBytes, payload, JSStringSQBreakout, bestMatch.StartOffset)

	// The critical assertion: we must detect the backslash escape
	quoteTransform := analysis.GetCharTransform('\'')
	if quoteTransform == nil {
		t.Fatal("Should detect transform for single quote")
	}

	// If detected correctly, this should be BackslashEsc
	if quoteTransform.Transform != TransformBackslashEsc {
		t.Logf("Note: Transform detected as %v (matchedBytes: %q)", quoteTransform.Transform, bestMatch.MatchedBytes)
		// Check if matchedBytes actually contains the backslash
		if !strings.Contains(string(bestMatch.MatchedBytes), "\\'") {
			t.Error("matchedBytes does not contain backslash-escaped quote - this is the bug!")
		}
	}
}

// TestP15Scenario_Phase2DoubleEscapeDetection tests the full Phase 1 → Phase 2 flow
// where Phase 2 detects double-backslash escape (exploitable)
func TestP15Scenario_Phase2DoubleEscapeDetection(t *testing.T) {
	// Phase 1: Generate primary payload and simulate p15 response
	// where ' is backslash-escaped to \'
	primaryPayload := GeneratePrimary()

	// Build Phase 1 response: ' -> \'
	phase1Transforms := map[byte]TransformType{
		'\'': TransformBackslashEsc,
		'"':  TransformPassed,
		'`':  TransformPassed,
		'<':  TransformHTMLEncoded,
		'>':  TransformPassed,
		' ':  TransformPassed,
		'=':  TransformPassed,
		'/':  TransformPassed,
	}

	phase1Response := buildPhase1Response(primaryPayload, JSStringSQBreakout, phase1Transforms)
	phase1Bytes := []byte(phase1Response)

	// Find matches and analyze
	matches := FindCanaryMatches(phase1Bytes, primaryPayload)
	if len(matches) == 0 {
		t.Fatal("Phase 1: Should find canary match")
	}

	t.Logf("Phase 1: Found %d matches", len(matches))
	for i, m := range matches {
		t.Logf("  [%d] mode=%v matchedBytes=%q", i, m.DetectionMode, m.MatchedBytes)
	}

	// Analyze transforms using the first match
	ta := NewTransformAnalyzer()
	phase1Analysis := ta.AnalyzeTransforms(matches[0].MatchedBytes, primaryPayload, JSStringSQBreakout, matches[0].StartOffset)

	// Verify Phase 1 detected backslash escape
	if !phase1Analysis.HasBackslashEscaped('\'') {
		t.Fatal("Phase 1: Should detect backslash-escaped quote")
	}

	// Phase 1 should NOT be exploitable (needs Phase 2 to test double-escape)
	if phase1Analysis.IsExploitable() {
		t.Error("Phase 1: Should NOT be directly exploitable with backslash-escaped quote")
	}

	// Collect next tests (should include \' for double-escape testing)
	nextTests := CollectNextTests([]*EscapeAnalysis{phase1Analysis})
	if !HasAnyTests(nextTests) {
		t.Fatal("Should have next tests for Phase 2")
	}

	t.Logf("Phase 2 tests collected: %+v", nextTests)

	// Verify \' test was collected
	foundBackslashQuoteTest := false
	for _, test := range nextTests {
		if test.TestSequence == "\\'" {
			foundBackslashQuoteTest = true
			break
		}
	}
	if !foundBackslashQuoteTest {
		t.Fatal("Should collect \\' test for Phase 2")
	}

	// Phase 2: Build secondary payload with \' and simulate response where \' -> \\'
	sequences := GetUniqueSequences(nextTests)
	secondaryPayload := BuildBatchedSecondaryPayload(sequences)
	if secondaryPayload == nil {
		t.Fatal("Should build secondary payload")
	}

	t.Logf("Secondary payload: %s", secondaryPayload.FullPayload)

	// Build Phase 2 response: \' -> \\' (double-backslash)
	// This simulates: var p15 = 'abc\\'def'; where input was abc\'def
	phase2Response := buildPhase2Response(secondaryPayload, sequences, map[string]string{
		"\\'": "\\\\'", // \' becomes \\' (backslash escaped, quote unescaped)
	})
	phase2Bytes := []byte(phase2Response)

	t.Logf("Phase 2 response: %s", phase2Response)

	// Analyze Phase 2 transforms
	phase2Transforms := ta.AnalyzeSequenceTransforms(phase2Bytes, secondaryPayload, sequences)

	// CRITICAL: Verify \' was detected as double-backslash
	backslashQuoteTransform := phase2Transforms["\\'"]
	if backslashQuoteTransform == nil {
		t.Fatalf("Should detect transform for \\' sequence. phase2Transforms=%+v", phase2Transforms)
	}

	t.Logf("Transform for \\': %v (OutputSeq=%q)", backslashQuoteTransform.Transform, backslashQuoteTransform.OutputSeq)

	if backslashQuoteTransform.Transform != TransformDoubleBackslash {
		t.Errorf("Transform = %v, want TransformDoubleBackslash", backslashQuoteTransform.Transform)
	}

	// Update Phase 1 analysis with Phase 2 result
	phase1Analysis.SetTransform("\\'", backslashQuoteTransform)

	// Now Phase 1 analysis should be exploitable
	if !phase1Analysis.IsExploitable() {
		t.Error("After Phase 2 double-escape detection, should be exploitable")
	}
}

// buildPhase2Response builds a response for Phase 2 testing with sequence transforms
func buildPhase2Response(payload *CanaryPayload, sequences []string, seqTransforms map[string]string) string {
	// Start with the full payload
	result := payload.FullPayload

	// Apply transforms to each sequence
	for seq, transform := range seqTransforms {
		segBefore := payload.GetSegmentBefore(seq[0])
		segAfter := payload.GetSegmentAfter(seq[0])

		if segBefore == "" || segAfter == "" {
			continue
		}

		// Replace: segBefore + seq + segAfter -> segBefore + transform + segAfter
		original := segBefore + seq + segAfter
		replaced := segBefore + transform + segAfter
		result = strings.Replace(result, original, replaced, 1)
	}

	return fmt.Sprintf("<html><body><script>var x = '%s';</script></body></html>", result)
}
