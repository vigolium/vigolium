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

func TestSessionToSessionHostname_StaticHeaders(t *testing.T) {
	s := &session.Session{
		Name:    "admin",
		Role:    session.RolePrimary,
		Headers: map[string]string{"Authorization": "Bearer tok1"},
	}

	sh := SessionToSessionHostname(s, 0)
	if sh == nil {
		t.Fatal("expected non-nil row")
	}
	if sh.SessionName != "admin" {
		t.Errorf("expected session_name=admin, got %q", sh.SessionName)
	}
	if sh.SessionRole != "primary" {
		t.Errorf("expected role=primary, got %q", sh.SessionRole)
	}
	if sh.Headers["Authorization"] != "Bearer tok1" {
		t.Errorf("expected Authorization header, got %v", sh.Headers)
	}
	if sh.Source != "cli" {
		t.Errorf("expected source=cli, got %q", sh.Source)
	}
	if sh.Position != 0 {
		t.Errorf("expected position=0, got %d", sh.Position)
	}
}

func TestSessionToSessionHostname_LoginFlow(t *testing.T) {
	s := &session.Session{
		Name: "user",
		Role: session.RoleCompare,
		Login: &session.LoginFlow{
			URL:         "https://example.com/login",
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"user":"test","pass":"test"}`,
			Extract: []session.ExtractRule{
				{Source: session.ExtractCookie, Name: "sid"},
			},
		},
	}

	sh := SessionToSessionHostname(s, 1)
	if sh == nil {
		t.Fatal("expected non-nil row")
	}
	if sh.LoginURL != "https://example.com/login" {
		t.Errorf("unexpected login_url: %q", sh.LoginURL)
	}
	if sh.LoginMethod != "POST" {
		t.Errorf("unexpected login_method: %q", sh.LoginMethod)
	}
	if sh.ExtractRules == "" {
		t.Error("expected non-empty extract_rules")
	}
	if sh.Position != 1 {
		t.Errorf("expected position=1, got %d", sh.Position)
	}
}

func TestSessionToSessionHostname_Nil(t *testing.T) {
	sh := SessionToSessionHostname(nil, 0)
	if sh != nil {
		t.Error("expected nil for nil input")
	}
}

func TestSessionsToSessionHostnames(t *testing.T) {
	sessions := []*session.Session{
		{Name: "admin", Role: session.RolePrimary, Headers: map[string]string{"Cookie": "s=1"}},
		{Name: "user", Role: session.RoleCompare, Headers: map[string]string{"Cookie": "s=2"}},
	}

	rows := SessionsToSessionHostnames(sessions, "proj-1", "example.com")
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	for _, row := range rows {
		if row.ProjectUUID != "proj-1" {
			t.Errorf("expected project_uuid=proj-1, got %q", row.ProjectUUID)
		}
		if row.Hostname != "example.com" {
			t.Errorf("expected hostname=example.com, got %q", row.Hostname)
		}
	}
	if rows[0].SessionName != "admin" || rows[1].SessionName != "user" {
		t.Errorf("unexpected session names: %q, %q", rows[0].SessionName, rows[1].SessionName)
	}
}

func TestSessionToSessionHostname_Roundtrip(t *testing.T) {
	original := &session.Session{
		Name:    "roundtrip",
		Role:    session.RolePrimary,
		Headers: map[string]string{"Authorization": "Bearer xyz"},
		Login: &session.LoginFlow{
			URL:         "https://app.com/api/login",
			Method:      "POST",
			ContentType: "application/json",
			Body:        `{"u":"a","p":"b"}`,
			Extract: []session.ExtractRule{
				{Source: session.ExtractJSON, Path: "$.token", ApplyAs: "Authorization: Bearer {value}"},
			},
		},
	}

	sh := SessionToSessionHostname(original, 0)
	restored := SessionHostnameToSession(sh)

	if restored.Name != original.Name {
		t.Errorf("name mismatch: %q vs %q", restored.Name, original.Name)
	}
	if restored.Role != original.Role {
		t.Errorf("role mismatch: %q vs %q", restored.Role, original.Role)
	}
	if restored.Login == nil {
		t.Fatal("expected non-nil Login after roundtrip")
	}
	if restored.Login.URL != original.Login.URL {
		t.Errorf("login URL mismatch: %q vs %q", restored.Login.URL, original.Login.URL)
	}
	if len(restored.Login.Extract) != 1 {
		t.Fatalf("expected 1 extract rule, got %d", len(restored.Login.Extract))
	}
	if restored.Login.Extract[0].ApplyAs != original.Login.Extract[0].ApplyAs {
		t.Errorf("apply_as mismatch: %q vs %q", restored.Login.Extract[0].ApplyAs, original.Login.Extract[0].ApplyAs)
	}
}
