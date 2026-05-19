package agent

import (
	"strings"
	"testing"
)

func TestSynthesizeAuthConfig_EmptyReturnsNil(t *testing.T) {
	cfg, err := SynthesizeAuthConfig(nil, nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when no inputs provided, got: %+v", cfg)
	}
}

func TestSynthesizeAuthConfig_CookiesAndHeaders(t *testing.T) {
	cfg, err := SynthesizeAuthConfig(
		[]string{"session=abc", "csrf=xyz; theme=dark"},
		[]string{"Authorization: Bearer foo", "X-Tenant: acme"},
		"",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || len(cfg.Sessions) != 1 {
		t.Fatalf("expected exactly 1 session, got: %+v", cfg)
	}
	s := cfg.Sessions[0]
	if s.Role != "primary" {
		t.Errorf("expected role 'primary', got %q", s.Role)
	}
	if got := s.Headers["Authorization"]; got != "Bearer foo" {
		t.Errorf("Authorization: want 'Bearer foo', got %q", got)
	}
	if got := s.Headers["X-Tenant"]; got != "acme" {
		t.Errorf("X-Tenant: want 'acme', got %q", got)
	}
	cookie := s.Headers["Cookie"]
	// All three pairs should land in the joined cookie value, in input order.
	for _, want := range []string{"session=abc", "csrf=xyz", "theme=dark"} {
		if !strings.Contains(cookie, want) {
			t.Errorf("cookie %q missing fragment %q", cookie, want)
		}
	}
}

func TestSynthesizeAuthConfig_HeaderCookieMergesWithFlagCookie(t *testing.T) {
	cfg, err := SynthesizeAuthConfig(
		[]string{"flag1=A"},
		[]string{"Cookie: hdr=B"},
		"",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := cfg.Sessions[0].Headers["Cookie"]
	if !strings.Contains(got, "hdr=B") || !strings.Contains(got, "flag1=A") {
		t.Errorf("expected merged Cookie containing both fragments, got: %q", got)
	}
}

func TestSynthesizeAuthConfig_LoginCurl(t *testing.T) {
	cmd := `curl -X POST https://example.com/api/login -H "Content-Type: application/json" -d '{"user":"admin","pass":"hunter2"}'`
	cfg, err := SynthesizeAuthConfig(nil, nil, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || len(cfg.Sessions) != 1 {
		t.Fatalf("expected 1 session, got: %+v", cfg)
	}
	login := cfg.Sessions[0].Login
	if login == nil {
		t.Fatal("expected Login flow to be populated")
	}
	if login.Method != "POST" {
		t.Errorf("Method: want POST, got %q", login.Method)
	}
	if login.URL != "https://example.com/api/login" {
		t.Errorf("URL: want https://example.com/api/login, got %q", login.URL)
	}
	if !strings.Contains(login.ContentType, "application/json") {
		t.Errorf("ContentType: want application/json, got %q", login.ContentType)
	}
	if !strings.Contains(login.Body, `"user":"admin"`) {
		t.Errorf("Body missing username payload, got: %q", login.Body)
	}
}

func TestSynthesizeAuthConfig_InvalidHeader(t *testing.T) {
	_, err := SynthesizeAuthConfig(nil, []string{"no-colon-here"}, "")
	if err == nil {
		t.Fatal("expected error for malformed header")
	}
}

func TestExtraHeadersFromAuth_PicksPrimary(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{Name: "secondary", Role: "compare", Headers: map[string]string{"X-Role": "compare"}},
			{Name: "main", Role: "primary", Headers: map[string]string{"X-Role": "primary", "Authorization": "Bearer x"}},
		},
	}
	got := ExtraHeadersFromAuth(cfg)
	if got["X-Role"] != "primary" {
		t.Errorf("primary session not picked: %+v", got)
	}
	if got["Authorization"] != "Bearer x" {
		t.Errorf("Authorization missing: %+v", got)
	}
}

func TestExtraHeadersFromAuth_NilSafe(t *testing.T) {
	if got := ExtraHeadersFromAuth(nil); got != nil {
		t.Errorf("expected nil for nil config, got: %+v", got)
	}
	if got := ExtraHeadersFromAuth(&AgentSessionConfig{}); got != nil {
		t.Errorf("expected nil for empty config, got: %+v", got)
	}
}

func TestJoinCookieValues_TrimsAndFlattens(t *testing.T) {
	got := joinCookieValues([]string{"  a=1 ;b=2 ", "c=3"})
	want := "a=1; b=2; c=3"
	if got != want {
		t.Errorf("joinCookieValues: want %q, got %q", want, got)
	}
}
