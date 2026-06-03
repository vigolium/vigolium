package csrf_detect

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// buildCtx assembles an HttpRequestResponse from a raw HTTP request for driving
// the passive scan method (no live server needed).
func buildCtx(t *testing.T, headers, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	svc, err := httpmsg.NewService("example.com", 443, "https")
	require.NoError(t, err)
	raw := "POST /transfer HTTP/1.1\r\nHost: example.com\r\n" + headers +
		fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

func scan(t *testing.T, headers, body string) int {
	t.Helper()
	res, err := New().ScanPerRequest(buildCtx(t, headers, body), &modkit.ScanContext{})
	require.NoError(t, err)
	return len(res)
}

func TestIsCSRFReachableContentType(t *testing.T) {
	reachable := []string{"", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain", "TEXT/PLAIN; charset=utf-8"}
	for _, ct := range reachable {
		assert.True(t, isCSRFReachableContentType(ct), "%q should be CSRF-reachable", ct)
	}
	notReachable := []string{"application/json", "application/json; charset=utf-8", "application/xml", "application/graphql"}
	for _, ct := range notReachable {
		assert.False(t, isCSRFReachableContentType(ct), "%q should not be CSRF-reachable", ct)
	}
}

// TestScanPerRequest_CookieFormNoToken_Flags is the true positive: a cookie-
// authenticated form POST with no anti-CSRF token, header, or SameSite.
func TestScanPerRequest_CookieFormNoToken_Flags(t *testing.T) {
	headers := "Content-Type: application/x-www-form-urlencoded\r\nCookie: session=abc123\r\n"
	assert.Equal(t, 1, scan(t, headers, "amount=1000&to=acct2"),
		"a cookie-auth form POST with no CSRF protection must be flagged")
}

// TestScanPerRequest_BearerNoCookie_NoFinding: header-based auth with no ambient
// cookie is not CSRF-able.
func TestScanPerRequest_BearerNoCookie_NoFinding(t *testing.T) {
	headers := "Content-Type: application/x-www-form-urlencoded\r\nAuthorization: Bearer eyJhbGci\r\n"
	assert.Equal(t, 0, scan(t, headers, "amount=1000"),
		"a Bearer-token request (no ambient cookie) must not be flagged")
}

// TestScanPerRequest_JSONBody_NoFinding: application/json cannot be forged by a
// cross-site form, so a missing token is not classic CSRF.
func TestScanPerRequest_JSONBody_NoFinding(t *testing.T) {
	headers := "Content-Type: application/json\r\nCookie: session=abc123\r\n"
	assert.Equal(t, 0, scan(t, headers, `{"amount":1000}`),
		"a JSON API request must not be flagged for missing CSRF token")
}

// TestScanPerRequest_NoCookie_NoFinding: without a session cookie there is no
// ambient credential for CSRF to ride.
func TestScanPerRequest_NoCookie_NoFinding(t *testing.T) {
	headers := "Content-Type: application/x-www-form-urlencoded\r\n"
	assert.Equal(t, 0, scan(t, headers, "amount=1000"),
		"a cookieless request must not be flagged")
}

// TestScanPerRequest_HasToken_NoFinding: a present CSRF token suppresses the
// finding (existing behavior, still holds under the new guards).
func TestScanPerRequest_HasToken_NoFinding(t *testing.T) {
	headers := "Content-Type: application/x-www-form-urlencoded\r\nCookie: session=abc123\r\n"
	assert.Equal(t, 0, scan(t, headers, "csrf_token=xyz&amount=1000"),
		"a request carrying a CSRF token must not be flagged")
}

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
