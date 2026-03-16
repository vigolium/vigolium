package database

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/session"
)

func TestSessionHostnameToSession_StaticHeaders(t *testing.T) {
	sh := &SessionHostname{
		SessionName: "api-key",
		SessionRole: "primary",
		Headers:     map[string]string{"X-API-Key": "secret123"},
	}

	s := SessionHostnameToSession(sh)
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.Name != "api-key" {
		t.Errorf("expected name=api-key, got %q", s.Name)
	}
	if s.Role != session.RolePrimary {
		t.Errorf("expected role=primary, got %q", s.Role)
	}
	if s.Headers["X-API-Key"] != "secret123" {
		t.Errorf("expected X-API-Key header, got %v", s.Headers)
	}
	if s.Login != nil {
		t.Error("expected nil Login for static-header session")
	}
}

func TestSessionHostnameToSession_LoginFlow(t *testing.T) {
	sh := &SessionHostname{
		SessionName:      "admin",
		SessionRole:      "primary",
		LoginURL:         "https://example.com/login",
		LoginMethod:      "POST",
		LoginContentType: "application/json",
		LoginBody:        `{"user":"admin","pass":"admin"}`,
		ExtractRules:     `[{"source":"cookie","name":"session_id"},{"source":"json","path":"$.token","apply_as":"Authorization: Bearer {value}"}]`,
	}

	s := SessionHostnameToSession(sh)
	if s == nil {
		t.Fatal("expected non-nil session")
	}
	if s.Login == nil {
		t.Fatal("expected non-nil Login")
	}
	if s.Login.URL != "https://example.com/login" {
		t.Errorf("unexpected login URL: %q", s.Login.URL)
	}
	if s.Login.Method != "POST" {
		t.Errorf("unexpected method: %q", s.Login.Method)
	}
	if s.Login.ContentType != "application/json" {
		t.Errorf("unexpected content type: %q", s.Login.ContentType)
	}
	if len(s.Login.Extract) != 2 {
		t.Fatalf("expected 2 extract rules, got %d", len(s.Login.Extract))
	}
	if s.Login.Extract[0].Source != session.ExtractCookie {
		t.Errorf("expected cookie source, got %q", s.Login.Extract[0].Source)
	}
	if s.Login.Extract[0].Name != "session_id" {
		t.Errorf("expected name=session_id, got %q", s.Login.Extract[0].Name)
	}
	if s.Login.Extract[1].ApplyAs != "Authorization: Bearer {value}" {
		t.Errorf("unexpected apply_as: %q", s.Login.Extract[1].ApplyAs)
	}
}

func TestSessionHostnameToSession_Nil(t *testing.T) {
	s := SessionHostnameToSession(nil)
	if s != nil {
		t.Error("expected nil for nil input")
	}
}

func TestSessionHostnamesToSessionConfig(t *testing.T) {
	rows := []*SessionHostname{
		{SessionName: "admin", SessionRole: "primary", Headers: map[string]string{"Authorization": "Bearer tok1"}},
		{SessionName: "user", SessionRole: "compare", Headers: map[string]string{"Authorization": "Bearer tok2"}},
	}

	cfg := SessionHostnamesToSessionConfig(rows)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(cfg.Sessions))
	}
	if cfg.Sessions[0].Name != "admin" {
		t.Errorf("expected first session=admin, got %q", cfg.Sessions[0].Name)
	}
	if cfg.Sessions[1].Role != session.RoleCompare {
		t.Errorf("expected second role=compare, got %q", cfg.Sessions[1].Role)
	}
}

func TestSessionHostnamesToSessionConfig_Empty(t *testing.T) {
	cfg := SessionHostnamesToSessionConfig(nil)
	if cfg != nil {
		t.Error("expected nil for empty input")
	}
}
