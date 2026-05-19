package authzutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainsEnforcementString_Positive(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"unauthorized", `{"error": "unauthorized"}`},
		{"forbidden", `{"message": "Forbidden"}`},
		{"access denied", `Access Denied: you cannot view this resource`},
		{"permission denied", `{"error": "Permission Denied"}`},
		{"requires authentication", `This resource requires authentication`},
		{"login required", `{"detail": "Login required"}`},
		{"not allowed", `You are not allowed to access this`},
		{"token expired", `{"error": "token expired"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, ContainsEnforcementString(tc.body), "body=%q", tc.body)
		})
	}
}

func TestContainsEnforcementString_Negative(t *testing.T) {
	tests := []string{
		`{"data": [1, 2, 3]}`,
		`{"user": "john", "email": "john@example.com"}`,
		`<html><body>Welcome</body></html>`,
		"",
	}

	for _, body := range tests {
		assert.False(t, ContainsEnforcementString(body), "body=%q", body)
	}
}

func TestContainsEnforcementString_CaseInsensitive(t *testing.T) {
	assert.True(t, ContainsEnforcementString("UNAUTHORIZED"))
	assert.True(t, ContainsEnforcementString("Access Denied"))
	assert.True(t, ContainsEnforcementString("PERMISSION DENIED"))
}

func TestContainsEnforcementString_TruncatesAt4KB(t *testing.T) {
	// Enforcement string at position > 4096 should not be detected
	body := strings.Repeat("x", 5000) + "unauthorized"
	assert.False(t, ContainsEnforcementString(body))

	// Enforcement string within first 4096 bytes should be detected
	body = strings.Repeat("x", 100) + "unauthorized" + strings.Repeat("x", 5000)
	assert.True(t, ContainsEnforcementString(body))
}

func TestIsLoginRedirect_Positive(t *testing.T) {
	tests := []struct {
		code     int
		location string
	}{
		{302, "/login"},
		{301, "/signin"},
		{302, "https://example.com/auth/login?next=/admin"},
		{303, "/sso/start"},
		{307, "/oauth/authorize"},
		{302, "/cas/login?service=http://app.example.com"},
	}

	for _, tc := range tests {
		assert.True(t, IsLoginRedirect(tc.code, tc.location),
			"code=%d location=%q", tc.code, tc.location)
	}
}

func TestIsLoginRedirect_Negative(t *testing.T) {
	tests := []struct {
		code     int
		location string
	}{
		{200, "/login"},      // Not a redirect
		{302, "/dashboard"},  // Not a login path
		{302, ""},            // Empty location
		{404, "/auth/login"}, // Not a redirect code
		{500, "/login"},      // Server error
	}

	for _, tc := range tests {
		assert.False(t, IsLoginRedirect(tc.code, tc.location),
			"code=%d location=%q", tc.code, tc.location)
	}
}
