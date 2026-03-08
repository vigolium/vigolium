package csrf_detect

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
		{"email", "email", false},
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

func TestCsrfHeaderPattern(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"X-CSRF-Token", "X-CSRF-Token", true},
		{"X-XSRF-TOKEN", "X-XSRF-TOKEN", true},
		{"X-Requested-With", "X-Requested-With", true},
		{"Content-Type", "Content-Type", false},
		{"Authorization", "Authorization", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := csrfHeaderPattern.MatchString(tt.header)
			if got != tt.expected {
				t.Errorf("csrfHeaderPattern.MatchString(%q) = %v, want %v", tt.header, got, tt.expected)
			}
		})
	}
}

func TestSameSitePattern(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		expected bool
	}{
		{"strict", "session=abc; SameSite=Strict; Secure", true},
		{"lax", "session=abc; SameSite=Lax; HttpOnly", true},
		{"none", "session=abc; SameSite=None; Secure", false},
		{"no samesite", "session=abc; HttpOnly; Secure", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sameSitePattern.MatchString(tt.cookie)
			if got != tt.expected {
				t.Errorf("sameSitePattern.MatchString(%q) = %v, want %v", tt.cookie, got, tt.expected)
			}
		})
	}
}
