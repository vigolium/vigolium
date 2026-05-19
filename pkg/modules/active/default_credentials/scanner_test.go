package default_credentials

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestDetectLoginEndpoint_FormEncoded(t *testing.T) {
	raw := []byte("POST /login HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"username=admin&password=secret&csrf_token=abc123")

	ctx, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}

	endpoint := detectLoginEndpoint(ctx)
	if endpoint == nil {
		t.Fatal("expected login endpoint to be detected")
	}

	if endpoint.usernameField != "username" {
		t.Errorf("usernameField = %q, want %q", endpoint.usernameField, "username")
	}
	if endpoint.passwordField != "password" {
		t.Errorf("passwordField = %q, want %q", endpoint.passwordField, "password")
	}
	if endpoint.isJSON {
		t.Error("isJSON should be false")
	}
}

func TestDetectLoginEndpoint_JSON(t *testing.T) {
	raw := []byte("POST /api/auth HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"email":"test@example.com","password":"pass123"}`)

	ctx, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}

	endpoint := detectLoginEndpoint(ctx)
	if endpoint == nil {
		t.Fatal("expected login endpoint to be detected")
	}

	if endpoint.usernameField != "email" {
		t.Errorf("usernameField = %q, want %q", endpoint.usernameField, "email")
	}
	if endpoint.passwordField != "password" {
		t.Errorf("passwordField = %q, want %q", endpoint.passwordField, "password")
	}
	if !endpoint.isJSON {
		t.Error("isJSON should be true")
	}
}

func TestDetectLoginEndpoint_NotLogin(t *testing.T) {
	raw := []byte("POST /api/search HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"query=test&page=1")

	ctx, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}

	endpoint := detectLoginEndpoint(ctx)
	if endpoint != nil {
		t.Error("expected nil for non-login endpoint")
	}
}

func TestDetectLoginEndpoint_WrongContentType(t *testing.T) {
	raw := []byte("POST /login HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: multipart/form-data\r\n\r\n" +
		"something")

	ctx, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		t.Fatalf("ParseRawRequest: %v", err)
	}

	endpoint := detectLoginEndpoint(ctx)
	if endpoint != nil {
		t.Error("expected nil for wrong content type")
	}
}

func TestIsLoginSuccess(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		body           string
		baselineStatus int
		baselineLength int
		hasSetCookie   bool
		want           bool
	}{
		{
			name:           "401 to 200 with cookie",
			statusCode:     200,
			body:           "Welcome to dashboard",
			baselineStatus: 401,
			baselineLength: 50,
			hasSetCookie:   true,
			want:           true,
		},
		{
			name:           "200 to 302 redirect",
			statusCode:     302,
			body:           "",
			baselineStatus: 200,
			baselineLength: 500,
			hasSetCookie:   false,
			want:           true,
		},
		{
			name:           "same response as baseline (no success)",
			statusCode:     200,
			body:           "Invalid credentials",
			baselineStatus: 200,
			baselineLength: 19,
			hasSetCookie:   false,
			want:           false,
		},
		{
			name:           "set cookie with significant body change",
			statusCode:     200,
			body:           string(make([]byte, 300)),
			baselineStatus: 200,
			baselineLength: 50,
			hasSetCookie:   true,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLoginSuccess(tt.statusCode, tt.body, tt.baselineStatus, tt.baselineLength, tt.hasSetCookie)
			if got != tt.want {
				t.Errorf("isLoginSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLockout(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"Account has been locked due to too many failed attempts", true},
		{"Rate limit exceeded. Try again later.", true},
		{"Invalid username or password", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			got := isLockout(tt.body)
			if got != tt.want {
				t.Errorf("isLockout(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestHasCAPTCHA(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{`<div class="g-recaptcha" data-sitekey="key"></div>`, true},
		{`<script src="https://hcaptcha.com/1/api.js"></script>`, true},
		{`<form><input name="username"></form>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			got := hasCAPTCHA(tt.body)
			if got != tt.want {
				t.Errorf("hasCAPTCHA() = %v, want %v", got, tt.want)
			}
		})
	}
}
