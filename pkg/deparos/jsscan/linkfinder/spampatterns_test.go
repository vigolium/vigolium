package linkfinder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsSpamPatternPositive tests inputs that SHOULD be detected as spam
func TestIsSpamPatternPositive(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		// Pattern 1: X_Y (uppercase/digit _ uppercase/digit/!)
		{"uppercase underscore pattern", "H_CH_!5H_"},
		{"digit underscore digit", "A_B"},
		{"mixed X_Y", "5_A"},
		{"with exclamation", "A_!"},

		// Pattern 2: digit_alphanumeric repeated 3+ times
		{"repeated X_ pattern", "A_B_C_D_"},
		{"digit underscore repeated", "1_2_3_4_"},
		{"mixed repeated", "A_1_B_2_C_"},

		// Pattern 3: 4+ consecutive special chars
		{"four underscores", "test____test"},
		{"four colons", "test::::test"},
		{"four dots", "test....test"},
		{"mixed special 4", "test_:._test"},
		{"five dashes", "test-----test"},

		// Pattern 4: High underscore + special char ratio
		{"high underscore ratio", "a_b_c_d_e!f@g"},
		{"many underscores and specials", "_!_@_#_$_%_"},

		// Pattern 5: Unicode spam chars + special chars
		{"unicode with underscore", "test·_value"},
		{"unicode with special", "¡<test>"},
		{"unicode latin chars", "üëè_test"},

		// Pattern 6: HTML tags
		{"opening tag", "test<div>content"},
		{"closing tag", "content</div>test"},
		{"self-closing tag", "<br/>test"},
		{"full tag", "<div class='foo'>bar</div>"},
		{"script tag", "<script>alert(1)</script>"},
		{"style tag", "<style>.foo{}</style>"},
		{"link tag", "<link rel='stylesheet'>"},
		{"meta tag", "<meta charset='utf-8'>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpamPattern(tt.input)
			assert.True(t, result, "Expected %q to be detected as spam", tt.input)
		})
	}
}

// TestIsSpamPatternNegative tests inputs that should NOT be detected as spam
func TestIsSpamPatternNegative(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		// Valid API paths
		{"api path", "/api/v1/users"},
		{"api with id", "/api/users/123"},
		{"nested path", "/api/v2/users/profile/settings"},

		// Valid URLs with underscores (but not spam pattern)
		{"path with underscore", "/user_profile"},
		{"filename with underscore", "/static/my_file.js"},

		// Valid query strings
		{"query string", "/search?q=test&page=1"},
		{"query with underscore", "/api?user_id=123"},

		// Valid paths with dots
		{"domain like", "api.example.com/path"},
		{"file extension", "/static/app.min.js"},

		// Empty and edge cases
		{"empty string", ""},
		{"just slash", "/"},
		{"simple path", "/users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpamPattern(tt.input)
			assert.False(t, result, "Expected %q to NOT be detected as spam", tt.input)
		})
	}
}

// TestSpamPatternEdgeCases tests boundary conditions
func TestSpamPatternEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Exactly 3 consecutive special chars (should NOT match - need 4+)
		{"three underscores", "test___test", false},
		{"three dots", "test...test", false},

		// Exactly 4 consecutive special chars (should match)
		{"four underscores", "test____test", true},

		// Leading slash should be stripped
		{"spam with leading slash", "/H_CH_!5H_", true},

		// Short strings with underscores
		// "a_b" is lowercase so doesn't match X_Y pattern [A-Z0-9]_[A-Z0-9!]
		{"short lowercase", "a_b", false},
		{"short uppercase matches X_Y", "A_B", true}, // Matches X_Y pattern
		{"short no spam", "abc", false},

		// Unicode chars without special chars (no spam)
		{"unicode only", "testüvalue", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpamPattern(tt.input)
			assert.Equal(t, tt.expected, result, "isSpamPattern(%q) = %v, want %v", tt.input, result, tt.expected)
		})
	}
}

// TestHTMLTagDetection specifically tests HTML tag detection
func TestHTMLTagDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Should detect as spam (HTML tags)
		{"div tag", "<div>content</div>", true},
		{"span tag", "<span class='foo'>text</span>", true},
		{"self-closing br", "<br/>", true},
		{"self-closing img", "<img src='x'/>", true},
		{"closing only", "text</p>more", true},
		{"opening only", "<p>text", true},

		// Should NOT detect as spam (not valid HTML tags)
		{"less than only", "a < b", false},
		{"greater than only", "a > b", false},
		{"math expression", "x<5 && y>3", false}, // Contains && which might be spam via blacklist
		{"arrow function", "x => y", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpamPattern(tt.input)
			assert.Equal(t, tt.expected, result, "isSpamPattern(%q) = %v, want %v", tt.input, result, tt.expected)
		})
	}
}

// TestUnderscoreRatioSpam tests the underscore + special char ratio detection
func TestUnderscoreRatioSpam(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// High ratio (> 30% underscore AND > 10% special) - spam
		// "_a_b_!" = 6 chars, 3 underscores (50%), 1 special (16%) -> spam
		{"high ratio spam", "_a_b_!", true},
		// "_!_@_#" = 6 chars, 3 underscores (50%), 3 special (50%) -> spam
		{"very high ratio", "_!_@_#", true},

		// Low ratio - not spam
		{"normal path", "/api/users/profile", false},
		{"some underscore", "user_name_value", false},
		// "_a_b_c!d@e#" = 11 chars, 3 underscores (27% < 30%) -> NOT spam
		{"below threshold", "_a_b_c!d@e#", false},

		// Short strings (len <= 5) - skip ratio check
		{"short", "a_b!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpamPattern(tt.input)
			assert.Equal(t, tt.expected, result, "isSpamPattern(%q) = %v, want %v", tt.input, result, tt.expected)
		})
	}
}
