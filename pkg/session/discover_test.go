package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsRawHTTPRequest(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"POST request", "POST /login HTTP/1.1\r\nHost: example.com\r\n", true},
		{"GET request", "GET /api/health HTTP/1.1\r\nHost: example.com\r\n", true},
		{"PUT request", "PUT /api/user HTTP/1.1\r\nHost: example.com\r\n", true},
		{"DELETE request", "DELETE /api/user/1 HTTP/1.1\r\nHost: example.com\r\n", true},
		{"with leading whitespace", "\n  POST /login HTTP/1.1\r\nHost: example.com\r\n", true},
		{"JSON object", `{"sessions": [{"name": "admin"}]}`, false},
		{"YAML sessions", "sessions:\n  - name: admin\n", false},
		{"empty", "", false},
		{"random text", "hello world", false},
		{"partial method", "POS /login HTTP/1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRawHTTPRequest([]byte(tt.data))
			if got != tt.want {
				t.Errorf("IsRawHTTPRequest(%q) = %v, want %v", tt.data[:min(len(tt.data), 40)], got, tt.want)
			}
		})
	}
}

func TestParseRawLoginRequest(t *testing.T) {
	raw := "POST /rest/user/login HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\nContent-Length: 51\r\n\r\n{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}"

	req, err := ParseRawLoginRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawLoginRequest: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL != "https://localhost:3000/rest/user/login" {
		t.Errorf("url = %q, want https://localhost:3000/rest/user/login", req.URL)
	}
	if req.Headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", req.Headers["Content-Type"])
	}
	if req.Body != `{"email":"admin@juice-sh.op","password":"admin123"}` {
		t.Errorf("body = %q", req.Body)
	}
	if req.Raw != raw {
		t.Error("Raw should be preserved")
	}
}

func TestParseRawLoginRequest_Port80(t *testing.T) {
	raw := "GET /health HTTP/1.1\r\nHost: example.com:80\r\n\r\n"
	req, err := ParseRawLoginRequest(raw)
	if err != nil {
		t.Fatalf("ParseRawLoginRequest: %v", err)
	}
	if req.URL != "http://example.com:80/health" {
		t.Errorf("url = %q, want http://example.com:80/health", req.URL)
	}
}

func TestParseRawLoginRequest_NoHost(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}"
	_, err := ParseRawLoginRequest(raw)
	if err == nil {
		t.Error("expected error for missing Host header")
	}
}

func TestParseRawLoginRequest_Empty(t *testing.T) {
	_, err := ParseRawLoginRequest("")
	if err == nil {
		t.Error("expected error for empty request")
	}
}

func TestDiscoverLogin_JSONToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": "eyJhbGciOiJIUzI1NiJ9.test-jwt-token",
		})
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/login",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"user":"admin","pass":"admin"}`,
		Raw:     "POST /login HTTP/1.1\r\nHost: localhost\r\n\r\n{}",
	}

	result, err := DiscoverLogin(loginReq)
	if err != nil {
		t.Fatalf("DiscoverLogin: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}
	if result.Session == nil {
		t.Fatal("expected non-nil session")
	}
	if result.Session.Headers["Authorization"] != "Bearer eyJhbGciOiJIUzI1NiJ9.test-jwt-token" {
		t.Errorf("Authorization = %q", result.Session.Headers["Authorization"])
	}
	if result.Session.Login == nil {
		t.Fatal("expected non-nil Login")
	}
	if len(result.Session.Login.Extract) == 0 {
		t.Fatal("expected extract rules")
	}
	if result.Session.Login.Extract[0].Source != ExtractJSON {
		t.Errorf("extract source = %q, want json", result.Session.Login.Extract[0].Source)
	}
	if result.Session.Login.Extract[0].Path != "token" {
		t.Errorf("extract path = %q, want token", result.Session.Login.Extract[0].Path)
	}
	if len(result.TokenSources) == 0 {
		t.Error("expected token sources")
	}
}

func TestDiscoverLogin_NestedJSONToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]string{
				"access_token": "nested-token-value",
			},
		})
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/auth",
		Headers: map[string]string{},
		Body:    `{"user":"a","pass":"b"}`,
	}

	result, err := DiscoverLogin(loginReq)
	if err != nil {
		t.Fatalf("DiscoverLogin: %v", err)
	}
	if result.Session == nil {
		t.Fatal("expected non-nil session")
	}
	if result.Session.Login.Extract[0].Path != "data.access_token" {
		t.Errorf("extract path = %q, want data.access_token", result.Session.Login.Extract[0].Path)
	}
}

func TestDiscoverLogin_CookieToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "abc123"})
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "xyz789"})
		w.WriteHeader(200)
		_, _ = fmt.Fprintln(w, "OK")
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/login",
		Headers: map[string]string{},
		Body:    "user=admin&pass=admin",
	}

	result, err := DiscoverLogin(loginReq)
	if err != nil {
		t.Fatalf("DiscoverLogin: %v", err)
	}
	if result.Session == nil {
		t.Fatal("expected non-nil session")
	}
	cookie := result.Session.Headers["Cookie"]
	if cookie == "" {
		t.Fatal("expected Cookie header")
	}
	if !contains(cookie, "session_id=abc123") {
		t.Errorf("Cookie = %q, missing session_id", cookie)
	}
	if !contains(cookie, "csrf=xyz789") {
		t.Errorf("Cookie = %q, missing csrf", cookie)
	}
}

func TestDiscoverLogin_AuthHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Token", "header-token-123")
		w.WriteHeader(200)
		_, _ = fmt.Fprintln(w, "OK")
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/login",
		Headers: map[string]string{},
		Body:    "user=admin&pass=admin",
	}

	result, err := DiscoverLogin(loginReq)
	if err != nil {
		t.Fatalf("DiscoverLogin: %v", err)
	}
	if result.Session == nil {
		t.Fatal("expected non-nil session")
	}
	if result.Session.Headers["X-Auth-Token"] != "header-token-123" {
		t.Errorf("X-Auth-Token = %q", result.Session.Headers["X-Auth-Token"])
	}
}

func TestDiscoverLogin_FailStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = fmt.Fprintln(w, "Unauthorized")
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/login",
		Headers: map[string]string{},
		Body:    `{"user":"bad","pass":"wrong"}`,
	}

	result, err := DiscoverLogin(loginReq)
	if err == nil {
		t.Error("expected error for 401")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.StatusCode != 401 {
		t.Errorf("status = %d, want 401", result.StatusCode)
	}
}

func TestDiscoverLogin_NoTokensFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "login successful",
			"user_id": "42",
		})
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/login",
		Headers: map[string]string{},
		Body:    `{"user":"admin","pass":"admin"}`,
	}

	_, err := DiscoverLogin(loginReq)
	if err == nil {
		t.Error("expected error when no tokens found")
	}
}

func TestDiscoverLogin_CombinedJSONAndCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session123"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token": "jwt-token-value",
		})
	}))
	defer ts.Close()

	loginReq := &LoginRequest{
		Method:  "POST",
		URL:     ts.URL + "/login",
		Headers: map[string]string{},
		Body:    `{"user":"admin","pass":"admin"}`,
	}

	result, err := DiscoverLogin(loginReq)
	if err != nil {
		t.Fatalf("DiscoverLogin: %v", err)
	}
	if result.Session == nil {
		t.Fatal("expected non-nil session")
	}
	// Should have both Authorization from JSON and Cookie from Set-Cookie.
	if result.Session.Headers["Authorization"] == "" {
		t.Error("expected Authorization header from JSON token")
	}
	if result.Session.Headers["Cookie"] == "" {
		t.Error("expected Cookie header from Set-Cookie")
	}
	if len(result.Session.Login.Extract) < 2 {
		t.Errorf("expected at least 2 extract rules, got %d", len(result.Session.Login.Extract))
	}
	if len(result.TokenSources) < 2 {
		t.Errorf("expected at least 2 token sources, got %d", len(result.TokenSources))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
