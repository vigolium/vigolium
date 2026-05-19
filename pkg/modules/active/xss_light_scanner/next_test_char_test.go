package xss_light_scanner

import (
	"testing"
)

// ============================================================================
// CollectNextTests Tests - Determines what to test in Phase 2
// ============================================================================

func TestCollectNextTests_JSStringSQ_BackslashEsc(t *testing.T) {
	// When ' is backslash-escaped, we need to test \'
	ea := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformBackslashEsc})
	ea.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	test := tests[0]
	if test.OriginalChar != '\'' {
		t.Errorf("OriginalChar = %q, want %q", test.OriginalChar, '\'')
	}
	if test.TestSequence != "\\'" {
		t.Errorf("TestSequence = %q, want %q", test.TestSequence, "\\'")
	}
	if test.Context != JSStringSQBreakout {
		t.Errorf("Context = %v, want JSStringSQBreakout", test.Context)
	}
	if test.SuccessCheck != TransformDoubleBackslash {
		t.Errorf("SuccessCheck = %v, want TransformDoubleBackslash", test.SuccessCheck)
	}
}

func TestCollectNextTests_JSStringSQ_QuotePassed_NoTest(t *testing.T) {
	// When ' passed through and ; is present, already exploitable - no further test needed
	ea := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformPassed})
	ea.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	// Already exploitable, no next tests needed
	if len(tests) != 0 {
		t.Errorf("Expected 0 tests (already exploitable), got %d", len(tests))
	}
}

func TestCollectNextTests_JSStringDQ_BackslashEsc(t *testing.T) {
	ea := NewEscapeAnalysis(JSStringDQBreakout, 0)
	ea.SetTransform("\"", &CharTransform{InputChar: '"', Transform: TransformBackslashEsc})
	ea.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	test := tests[0]
	if test.OriginalChar != '"' {
		t.Errorf("OriginalChar = %q, want %q", test.OriginalChar, '"')
	}
	if test.TestSequence != "\\\"" {
		t.Errorf("TestSequence = %q, want %q", test.TestSequence, "\\\"")
	}
	if test.Context != JSStringDQBreakout {
		t.Errorf("Context = %v, want JSStringDQBreakout", test.Context)
	}
}

func TestCollectNextTests_JSTemplateLiteral_BackslashEsc(t *testing.T) {
	ea := NewEscapeAnalysis(JSTemplateLiteral, 0)
	ea.SetTransform("`", &CharTransform{InputChar: '`', Transform: TransformBackslashEsc})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	test := tests[0]
	if test.OriginalChar != '`' {
		t.Errorf("OriginalChar = %q, want %q", test.OriginalChar, '`')
	}
	if test.TestSequence != "\\`" {
		t.Errorf("TestSequence = %q, want %q", test.TestSequence, "\\`")
	}
}

func TestCollectNextTests_HTMLAttributeValueDQ_BackslashEsc(t *testing.T) {
	// Unusual for HTML but possible in some frameworks
	ea := NewEscapeAnalysis(HTMLAttributeValueDQBreakout, 0)
	ea.SetTransform("\"", &CharTransform{InputChar: '"', Transform: TransformBackslashEsc})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	test := tests[0]
	if test.TestSequence != "\\\"" {
		t.Errorf("TestSequence = %q, want %q", test.TestSequence, "\\\"")
	}
	if test.Context != HTMLAttributeValueDQBreakout {
		t.Errorf("Context = %v, want HTMLAttributeValueDQBreakout", test.Context)
	}
}

func TestCollectNextTests_HTMLAttributeValueSQ_BackslashEsc(t *testing.T) {
	ea := NewEscapeAnalysis(HTMLAttributeValueSQBreakout, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformBackslashEsc})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	test := tests[0]
	if test.TestSequence != "\\'" {
		t.Errorf("TestSequence = %q, want %q", test.TestSequence, "\\'")
	}
}

func TestCollectNextTests_HTMLAttributeValueBT_BackslashEsc(t *testing.T) {
	ea := NewEscapeAnalysis(HTMLAttributeValueBTBreakout, 0)
	ea.SetTransform("`", &CharTransform{InputChar: '`', Transform: TransformBackslashEsc})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	test := tests[0]
	if test.TestSequence != "\\`" {
		t.Errorf("TestSequence = %q, want %q", test.TestSequence, "\\`")
	}
}

// ============================================================================
// No Test Needed Cases
// ============================================================================

func TestCollectNextTests_HTMLGeneric_NoTest(t *testing.T) {
	// HTMLGeneric doesn't have backslash escape scenarios
	ea := NewEscapeAnalysis(HTMLGeneric, 0)
	ea.SetTransform("<", &CharTransform{InputChar: '<', Transform: TransformHTMLEncoded})
	ea.SetTransform(">", &CharTransform{InputChar: '>', Transform: TransformHTMLEncoded})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 0 {
		t.Errorf("Expected 0 tests for HTMLGeneric, got %d", len(tests))
	}
}

func TestCollectNextTests_EventHandler_AlwaysExploitable(t *testing.T) {
	// Event handlers are always exploitable, no further tests needed
	contexts := []ReflectionContext{
		JSInEventHandlerDQ,
		JSInEventHandlerSQ,
		JSInEventHandlerBT,
		JSInEventHandlerUnquoted,
	}

	for _, ctx := range contexts {
		t.Run(ctx.String(), func(t *testing.T) {
			ea := NewEscapeAnalysis(ctx, 0)
			tests := CollectNextTests([]*EscapeAnalysis{ea})

			if len(tests) != 0 {
				t.Errorf("Expected 0 tests for %s (always exploitable), got %d", ctx, len(tests))
			}
		})
	}
}

func TestCollectNextTests_JSCodeStatement_AlwaysExploitable(t *testing.T) {
	ea := NewEscapeAnalysis(JSCodeStatement, 0)
	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 0 {
		t.Errorf("Expected 0 tests for JSCodeStatement (always exploitable), got %d", len(tests))
	}
}

func TestCollectNextTests_HTMLEncoded_NoTest(t *testing.T) {
	// When quote is HTML encoded, no double-escape test is relevant
	ea := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformHTMLEncoded})
	ea.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	tests := CollectNextTests([]*EscapeAnalysis{ea})

	if len(tests) != 0 {
		t.Errorf("Expected 0 tests when quote is HTML encoded, got %d", len(tests))
	}
}

// ============================================================================
// Multiple Analyses Tests
// ============================================================================

func TestCollectNextTests_MultipleAnalyses(t *testing.T) {
	// Two different contexts needing tests
	ea1 := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea1.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformBackslashEsc})
	ea1.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	ea2 := NewEscapeAnalysis(JSStringDQBreakout, 100)
	ea2.SetTransform("\"", &CharTransform{InputChar: '"', Transform: TransformBackslashEsc})
	ea2.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	tests := CollectNextTests([]*EscapeAnalysis{ea1, ea2})

	if len(tests) != 2 {
		t.Fatalf("Expected 2 tests, got %d", len(tests))
	}

	// Check both sequences are present
	seqs := make(map[string]bool)
	for _, test := range tests {
		seqs[test.TestSequence] = true
	}

	if !seqs["\\'"] {
		t.Error("Missing \\' test sequence")
	}
	if !seqs["\\\""] {
		t.Error("Missing \\\" test sequence")
	}
}

func TestCollectNextTests_Deduplication(t *testing.T) {
	// Two analyses with the same context should produce only one test
	ea1 := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea1.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformBackslashEsc})
	ea1.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	ea2 := NewEscapeAnalysis(JSStringSQBreakout, 100)
	ea2.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformBackslashEsc})
	ea2.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})

	tests := CollectNextTests([]*EscapeAnalysis{ea1, ea2})

	// Should be deduplicated to 1 test
	if len(tests) != 1 {
		t.Errorf("Expected 1 test (deduplicated), got %d", len(tests))
	}

	if tests[0].TestSequence != "\\'" {
		t.Errorf("TestSequence = %q, want %q", tests[0].TestSequence, "\\'")
	}
}

func TestCollectNextTests_MixedExploitableAndNot(t *testing.T) {
	// One exploitable (no test needed), one needs test
	ea1 := NewEscapeAnalysis(JSStringSQBreakout, 0)
	ea1.SetTransform("'", &CharTransform{InputChar: '\'', Transform: TransformPassed})
	ea1.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})
	// ea1 is exploitable - no test needed

	ea2 := NewEscapeAnalysis(JSStringDQBreakout, 100)
	ea2.SetTransform("\"", &CharTransform{InputChar: '"', Transform: TransformBackslashEsc})
	ea2.SetTransform(";", &CharTransform{InputChar: ';', Transform: TransformPassed})
	// ea2 needs test

	tests := CollectNextTests([]*EscapeAnalysis{ea1, ea2})

	if len(tests) != 1 {
		t.Fatalf("Expected 1 test, got %d", len(tests))
	}

	if tests[0].TestSequence != "\\\"" {
		t.Errorf("TestSequence = %q, want %q", tests[0].TestSequence, "\\\"")
	}
}

func TestCollectNextTests_Empty(t *testing.T) {
	tests := CollectNextTests([]*EscapeAnalysis{})

	if len(tests) != 0 {
		t.Errorf("Expected 0 tests for empty input, got %d", len(tests))
	}

	tests = CollectNextTests(nil)

	if len(tests) != 0 {
		t.Errorf("Expected 0 tests for nil input, got %d", len(tests))
	}
}

// ============================================================================
// Helper Functions Tests
// ============================================================================

func TestHasAnyTests(t *testing.T) {
	tests := []struct {
		name     string
		input    []NextCharTest
		expected bool
	}{
		{"Empty", []NextCharTest{}, false},
		{"Nil", nil, false},
		{"OneTest", []NextCharTest{{TestSequence: "\\'"}}, true},
		{"MultipleTests", []NextCharTest{{TestSequence: "\\'"}, {TestSequence: "\\\""}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasAnyTests(tt.input); got != tt.expected {
				t.Errorf("HasAnyTests() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetUniqueSequences(t *testing.T) {
	tests := []struct {
		name     string
		input    []NextCharTest
		expected []string
	}{
		{"Empty", []NextCharTest{}, nil},
		{"SingleTest", []NextCharTest{{TestSequence: "\\'"}}, []string{"\\'"}},
		{"MultipleUnique", []NextCharTest{
			{TestSequence: "\\'"},
			{TestSequence: "\\\""},
		}, []string{"\\'", "\\\""}},
		{"Duplicates", []NextCharTest{
			{TestSequence: "\\'"},
			{TestSequence: "\\'"},
			{TestSequence: "\\\""},
		}, []string{"\\'", "\\\""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetUniqueSequences(tt.input)

			if len(got) != len(tt.expected) {
				t.Fatalf("GetUniqueSequences() length = %d, want %d", len(got), len(tt.expected))
			}

			// Check all expected sequences are present
			gotSet := make(map[string]bool)
			for _, seq := range got {
				gotSet[seq] = true
			}
			for _, exp := range tt.expected {
				if !gotSet[exp] {
					t.Errorf("Missing expected sequence %q", exp)
				}
			}
		})
	}
}
