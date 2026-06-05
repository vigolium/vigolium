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

// keycloakLoginBody is a trimmed copy of the Keycloak Sign-In form that
// triggered the idor-guid false positive — a predicted header value returned
// this page and the naive "200 + body differs" oracle fired on the per-request
// session_code/execution tokens.
const keycloakLoginBody = `<!DOCTYPE html><html><body>
<form id="kc-form-login" action="https://kc.example.com/realms/master/login-actions/authenticate?session_code=Lc1mxTOrA60dKt7KZrAY4GdR5iL_aUt-UOW5G-SE2d0&amp;execution=fc587d0a-f783-4698-85ec-a824ce3d567e" method="post">
  <input id="username" name="username" value="" type="text" autocomplete="username" autofocus/>
  <input id="password" name="password" value="" type="password" autocomplete="current-password"/>
  <button class="pf-v5-c-button pf-m-primary" name="login" id="kc-login" type="submit">Sign In</button>
</form>
</body></html>`

func TestIsAuthChallengePage_Positive(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"keycloak login form", keycloakLoginBody},
		{"bare password field", `<form><input type="password" name="pw"></form>`},
		{"single-quoted password field", `<input type='password'>`},
		{"current-password autocomplete", `<input autocomplete="current-password">`},
		{"j_security_check action", `<form action="/j_security_check" method="post">`},
		{"oidc auth endpoint", `<a href="/realms/x/protocol/openid-connect/auth?client_id=app">login</a>`},
		{"oauth authorize", `<meta http-equiv="refresh" content="0;url=/oauth/authorize?client_id=app">`},
		{"access denied notice", `{"error":"forbidden","message":"access denied"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, IsAuthChallengePage(tc.body), "body=%q", tc.body)
		})
	}
}

func TestIsAuthChallengePage_Negative(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"json object", `{"id":101,"owner":"user-101","secret":"token-101","balance":4200}`},
		{"plain html page", `<html><body><h1>Order #101</h1><p>Shipped to user-101</p></body></html>`},
		{"nav mentions sign in only", `<html><body><nav><a href="/account">My account</a></nav>Welcome back, user-101</body></html>`},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, IsAuthChallengePage(tc.body), "body=%q", tc.body)
		})
	}
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
