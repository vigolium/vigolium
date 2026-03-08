package csrf_verify

import (
	"testing"
)

func TestCsrfParamPattern(t *testing.T) {
	tests := []struct {
		name     string
		param    string
		expected bool
	}{
		{"csrf_token", "csrf_token", true},
		{"_token", "_token", true},
		{"xsrf-token", "xsrf-token", true},
		{"authenticity_token", "authenticity_token", true},
		{"csrfmiddlewaretoken", "csrfmiddlewaretoken", true},
		{"__RequestVerificationToken", "__RequestVerificationToken", true},
		{"nonce", "nonce", true},
		{"username", "username", false},
		{"password", "password", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csrfParamPattern.MatchString(tt.param)
			if got != tt.expected {
				t.Errorf("csrfParamPattern.MatchString(%q) = %v, want %v", tt.param, got, tt.expected)
			}
		})
	}
}

func TestSameStatusClass(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected bool
	}{
		{"both 200", 200, 201, true},
		{"200 vs 301", 200, 301, false},
		{"403 vs 401", 403, 401, true},
		{"200 vs 500", 200, 500, false},
		{"302 vs 301", 302, 301, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sameStatusClass(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("sameStatusClass(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}
