package condition

import (
	"strings"
	"testing"
)

// TestEscapeJSString verifies JS string escaping prevents injection.
// HIGH PRIORITY: Security-critical test.
func TestEscapeJSString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain string",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "single quotes",
			input: "it's a test",
			want:  `it\'s a test`,
		},
		{
			name:  "backslashes",
			input: `path\to\file`,
			want:  `path\\to\\file`,
		},
		{
			name:  "newlines",
			input: "line1\nline2",
			want:  `line1\nline2`,
		},
		{
			name:  "carriage returns",
			input: "line1\rline2",
			want:  `line1\rline2`,
		},
		{
			name:  "tabs",
			input: "col1\tcol2",
			want:  `col1\tcol2`,
		},
		{
			name:  "mixed special chars",
			input: "it's\na\\test\twith\rspecials",
			want:  `it\'s\na\\test\twith\rspecials`,
		},
		{
			name:  "injection attempt",
			input: "'; alert('xss'); '",
			want:  `\'; alert(\'xss\'); \'`,
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "backslash before quote",
			input: `\'already escaped`,
			want:  `\\\'already escaped`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeJSString(tt.input)
			if got != tt.want {
				t.Errorf("escapeJSString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestEscapeJSStringRoundTrip verifies escaped strings are safe for JS embedding.
func TestEscapeJSStringRoundTrip(t *testing.T) {
	// These strings should be safe to embed in JS single quotes after escaping
	inputs := []string{
		"simple",
		"with spaces",
		"with'quotes",
		"with\"double\"quotes",
		"with\\backslash",
		"with\nnewline",
		"multi\nline\ntext",
		"tab\there",
		"mixed\n\t\\'\r",
	}

	for _, input := range inputs {
		escaped := escapeJSString(input)

		// Should not contain unescaped single quotes
		if strings.Contains(escaped, "'") && !strings.Contains(escaped, `\'`) {
			t.Errorf("escapeJSString(%q) contains unescaped single quote", input)
		}

		// Should not contain raw newlines
		if strings.Contains(escaped, "\n") {
			t.Errorf("escapeJSString(%q) contains raw newline", input)
		}
	}
}

// TestJSHelperExpressions verifies JavaScript helper expression format.
func TestJSHelperExpressions(t *testing.T) {
	// Verify constant expressions are valid JS
	constants := map[string]string{
		"JSDocumentReady": JSDocumentReady,
		"JSNoLoading":     JSNoLoading,
		"JSNoAjaxPending": JSNoAjaxPending,
		"JSAngularReady":  JSAngularReady,
		"JSReactReady":    JSReactReady,
		"JSVueReady":      JSVueReady,
		"JSjQueryReady":   JSjQueryReady,
	}

	for name, expr := range constants {
		t.Run(name, func(t *testing.T) {
			if expr == "" {
				t.Errorf("%s is empty", name)
			}
			// Basic syntax check - should not be empty and should not have unbalanced quotes
			if strings.Count(expr, "'")%2 != 0 {
				t.Errorf("%s has unbalanced single quotes", name)
			}
		})
	}
}

// TestJSElementInViewport verifies JSElementInViewport expression generation.
func TestJSElementInViewport(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		want     string
	}{
		{
			name:     "simple selector",
			selector: "#element",
			want:     "#element",
		},
		{
			name:     "selector with quotes",
			selector: "button[data-action='submit']",
			want:     `button[data-action=\'submit\']`,
		},
		{
			name:     "class selector",
			selector: ".my-class",
			want:     ".my-class",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := JSElementInViewport(tt.selector)

			if !strings.Contains(expr, tt.want) {
				t.Errorf("JSElementInViewport(%q) does not contain %q", tt.selector, tt.want)
			}

			// Verify it's an IIFE
			if !strings.Contains(expr, "(function()") {
				t.Error("JSElementInViewport should return an IIFE")
			}
			if !strings.Contains(expr, "getBoundingClientRect") {
				t.Error("JSElementInViewport should use getBoundingClientRect")
			}
		})
	}
}

// TestJSElementHasText verifies JSElementHasText expression generation.
func TestJSElementHasText(t *testing.T) {
	tests := []struct {
		name         string
		selector     string
		text         string
		wantSelector string
		wantText     string
	}{
		{
			name:         "simple",
			selector:     "#element",
			text:         "Hello",
			wantSelector: "#element",
			wantText:     "Hello",
		},
		{
			name:         "text with quotes",
			selector:     "#element",
			text:         "it's here",
			wantSelector: "#element",
			wantText:     `it\'s here`,
		},
		{
			name:         "selector with special chars",
			selector:     "button[name='submit']",
			text:         "Submit",
			wantSelector: `button[name=\'submit\']`,
			wantText:     "Submit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := JSElementHasText(tt.selector, tt.text)

			if !strings.Contains(expr, tt.wantSelector) {
				t.Errorf("JSElementHasText does not contain expected selector %q", tt.wantSelector)
			}
			if !strings.Contains(expr, tt.wantText) {
				t.Errorf("JSElementHasText does not contain expected text %q", tt.wantText)
			}
			if !strings.Contains(expr, "textContent.includes") {
				t.Error("JSElementHasText should use textContent.includes")
			}
		})
	}
}

// TestJSFormValid verifies JSFormValid expression generation.
func TestJSFormValid(t *testing.T) {
	tests := []struct {
		name         string
		selector     string
		wantSelector string
	}{
		{
			name:         "form by ID",
			selector:     "#myForm",
			wantSelector: "#myForm",
		},
		{
			name:         "form by name",
			selector:     "form[name='login']",
			wantSelector: `form[name=\'login\']`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := JSFormValid(tt.selector)

			if !strings.Contains(expr, tt.wantSelector) {
				t.Errorf("JSFormValid does not contain expected selector %q", tt.wantSelector)
			}
			if !strings.Contains(expr, "checkValidity") {
				t.Error("JSFormValid should use checkValidity")
			}
		})
	}
}

// TestJSInjectionPrevention verifies escaping prevents JS injection.
func TestJSInjectionPrevention(t *testing.T) {
	injectionAttempts := []struct {
		input       string
		description string
	}{
		{"'); alert('xss'); //", "basic quote injection"},
		{"'+ window.location='http://evil.com'+'", "assignment injection"},
		{"'; document.cookie; '", "cookie access"},
		{"</script><script>alert(1)</script>", "script tag injection"},
		{"\\'; alert(1); //", "escaped quote bypass"},
	}

	for _, tc := range injectionAttempts {
		t.Run("injection:"+tc.description, func(t *testing.T) {
			escaped := escapeJSString(tc.input)

			// Key security check: All single quotes in the input must be escaped
			// The escaped version should have \' where original had '
			originalQuotes := strings.Count(tc.input, "'")
			escapedQuotes := strings.Count(escaped, `\'`)

			// Every original quote should be escaped
			if escapedQuotes < originalQuotes {
				t.Errorf("Not all quotes escaped in %q: original has %d quotes, escaped has %d \\' sequences",
					tc.input, originalQuotes, escapedQuotes)
			}

			// Additional check: Verify backslashes are also escaped
			// This prevents bypass attempts like \' which would become \\' after escaping
			originalBackslashes := strings.Count(tc.input, `\`)
			escapedBackslashes := strings.Count(escaped, `\\`)
			if escapedBackslashes < originalBackslashes {
				t.Errorf("Not all backslashes escaped in %q", tc.input)
			}

			// Verify the escape function produces different output for dangerous input
			if strings.Contains(tc.input, "'") && tc.input == escaped {
				t.Errorf("Dangerous input %q was not modified by escaping", tc.input)
			}
		})
	}
}

// TestJSExpressionConstants verifies predefined JS expressions.
func TestJSExpressionConstants(t *testing.T) {
	// Verify expressions are non-empty and syntactically reasonable
	expressions := []struct {
		name  string
		value string
	}{
		{"JSDocumentReady", JSDocumentReady},
		{"JSNoLoading", JSNoLoading},
		{"JSNoAjaxPending", JSNoAjaxPending},
		{"JSAngularReady", JSAngularReady},
		{"JSReactReady", JSReactReady},
		{"JSVueReady", JSVueReady},
		{"JSjQueryReady", JSjQueryReady},
	}

	for _, expr := range expressions {
		t.Run(expr.name, func(t *testing.T) {
			if len(expr.value) == 0 {
				t.Errorf("%s should not be empty", expr.name)
			}

			// Basic balance checks
			opens := strings.Count(expr.value, "(")
			closes := strings.Count(expr.value, ")")
			if opens != closes {
				t.Errorf("%s has unbalanced parentheses: %d opens, %d closes",
					expr.name, opens, closes)
			}

			braceOpens := strings.Count(expr.value, "{")
			braceCloses := strings.Count(expr.value, "}")
			if braceOpens != braceCloses {
				t.Errorf("%s has unbalanced braces: %d opens, %d closes",
					expr.name, braceOpens, braceCloses)
			}
		})
	}
}
