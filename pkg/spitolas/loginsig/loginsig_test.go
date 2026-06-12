package loginsig

import (
	"net/url"
	"testing"
)

func TestLooksLikeLoginURL(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		// IdP hosts
		{"https://login.microsoftonline.com/common/oauth2/authorize", true},
		{"https://accounts.google.com/o/oauth2/v2/auth", true},
		{"https://tenant.okta.com/app/x", true},
		{"https://acme.auth0.com/authorize", true},
		// login host prefixes
		{"https://login.example.com/", true},
		{"https://sso.example.com/start", true},
		{"https://idp.example.com/", true},
		// login path markers on an ordinary host
		{"https://app.example.com/oauth2/authorize?response_type=code", true},
		{"https://app.example.com/saml/acs", true},
		{"https://app.example.com/signin", true},
		{"https://app.example.com/login", true},
		// not login
		{"https://app.example.com/console/", false},
		{"https://app.example.com/dashboard", false},
		{"https://api.example.com/v1/users", false},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.raw, err)
		}
		if got := LooksLikeLoginURL(u); got != tt.want {
			t.Errorf("LooksLikeLoginURL(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
	if LooksLikeLoginURL(nil) {
		t.Errorf("LooksLikeLoginURL(nil) should be false")
	}
}

func TestBodyLooksLikeLogin(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"password input double quotes", `<input type="password" name="p">`, true},
		{"password input single quotes", `<input type='password'>`, true},
		{"password input unquoted", `<input type=password>`, true},
		{"uppercase TYPE", `<INPUT TYPE="PASSWORD">`, true},
		{"no password field", `<form><input type="text"><button>Go</button></form>`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		if got := BodyLooksLikeLogin([]byte(tt.body)); got != tt.want {
			t.Errorf("%s: BodyLooksLikeLogin = %v, want %v", tt.name, got, tt.want)
		}
	}
}
