package xss_light_scanner

// NextCharTest defines what to test in Phase 2 (batched secondary payload)
type NextCharTest struct {
	OriginalChar byte              // The original char that was escaped (e.g., ')
	TestSequence string            // What to send (e.g., "\\'")
	Context      ReflectionContext // Which context this test is for
	SuccessCheck TransformType     // What transform indicates success
}

// CollectNextTests analyzes Phase 1 results and returns needed tests for Phase 2
// This aggregates all tests across all reflection points and deduplicates
func CollectNextTests(analyses []*EscapeAnalysis) []NextCharTest {
	testsMap := make(map[string]NextCharTest) // Key by TestSequence to dedupe

	for _, ea := range analyses {
		// Skip if already exploitable
		if ea.IsExploitable() {
			continue
		}

		tests := collectTestsForContext(ea)
		for _, test := range tests {
			// Deduplicate by test sequence - keep first occurrence
			if _, exists := testsMap[test.TestSequence]; !exists {
				testsMap[test.TestSequence] = test
			}
		}
	}

	// Convert map to slice
	result := make([]NextCharTest, 0, len(testsMap))
	for _, test := range testsMap {
		result = append(result, test)
	}

	return result
}

// collectTestsForContext returns tests needed for a specific context
func collectTestsForContext(ea *EscapeAnalysis) []NextCharTest {
	var tests []NextCharTest

	switch ea.Context {
	case JSStringSQBreakout:
		// If ' was backslash-escaped, test \'
		if ea.HasBackslashEscaped('\'') {
			tests = append(tests, NextCharTest{
				OriginalChar: '\'',
				TestSequence: "\\'",
				Context:      JSStringSQBreakout,
				SuccessCheck: TransformDoubleBackslash,
			})
		}

	case JSStringDQBreakout:
		// If " was backslash-escaped, test \"
		if ea.HasBackslashEscaped('"') {
			tests = append(tests, NextCharTest{
				OriginalChar: '"',
				TestSequence: "\\\"",
				Context:      JSStringDQBreakout,
				SuccessCheck: TransformDoubleBackslash,
			})
		}

	case JSTemplateLiteral:
		// If ` was backslash-escaped, test \`
		if ea.HasBackslashEscaped('`') {
			tests = append(tests, NextCharTest{
				OriginalChar: '`',
				TestSequence: "\\`",
				Context:      JSTemplateLiteral,
				SuccessCheck: TransformDoubleBackslash,
			})
		}

	case HTMLAttributeValueDQBreakout:
		// If " was backslash-escaped (unusual for HTML but possible), test \"
		if ea.HasBackslashEscaped('"') {
			tests = append(tests, NextCharTest{
				OriginalChar: '"',
				TestSequence: "\\\"",
				Context:      HTMLAttributeValueDQBreakout,
				SuccessCheck: TransformDoubleBackslash,
			})
		}

	case HTMLAttributeValueSQBreakout:
		// If ' was backslash-escaped, test \'
		if ea.HasBackslashEscaped('\'') {
			tests = append(tests, NextCharTest{
				OriginalChar: '\'',
				TestSequence: "\\'",
				Context:      HTMLAttributeValueSQBreakout,
				SuccessCheck: TransformDoubleBackslash,
			})
		}

	case HTMLAttributeValueBTBreakout:
		// If ` was backslash-escaped, test \`
		if ea.HasBackslashEscaped('`') {
			tests = append(tests, NextCharTest{
				OriginalChar: '`',
				TestSequence: "\\`",
				Context:      HTMLAttributeValueBTBreakout,
				SuccessCheck: TransformDoubleBackslash,
			})
		}
	}

	return tests
}

// HasAnyTests returns true if there are any tests to run
func HasAnyTests(tests []NextCharTest) bool {
	return len(tests) > 0
}

// GetUniqueSequences returns unique test sequences for payload building
func GetUniqueSequences(tests []NextCharTest) []string {
	seen := make(map[string]bool)
	var result []string

	for _, test := range tests {
		if !seen[test.TestSequence] {
			seen[test.TestSequence] = true
			result = append(result, test.TestSequence)
		}
	}

	return result
}
