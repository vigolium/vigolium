package authsession

import (
	"encoding/json"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
)

func TestAgentSessionConfigToAuthenticationHostnames(t *testing.T) {
	cfg := &agenttypes.AgentSessionConfig{
		Sessions: []agenttypes.AgentSessionEntry{
			{
				Name:    "admin",
				Role:    "primary",
				Headers: map[string]string{"X-API-Key": "key123"},
			},
			{
				Name: "user",
				Role: "compare",
				Login: &agenttypes.AgentLoginFlow{
					URL:         "https://app.com/api/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"username":"user","password":"pass"}`,
					Extract: []agenttypes.AgentExtractRule{
						{Source: "json", Path: "$.access_token", ApplyAs: "Authorization: Bearer {value}"},
						{Source: "cookie", Name: "sid"},
					},
				},
			},
		},
	}

	rows := AgentSessionConfigToAuthenticationHostnames(cfg, "proj-1", "scan-1", "app.com", "agent-swarm")

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	// First row: static headers
	r0 := rows[0]
	if r0.ProjectUUID != "proj-1" {
		t.Errorf("expected project_uuid=proj-1, got %q", r0.ProjectUUID)
	}
	if r0.ScanUUID != "scan-1" {
		t.Errorf("expected scan_uuid=scan-1, got %q", r0.ScanUUID)
	}
	if r0.Hostname != "app.com" {
		t.Errorf("expected hostname=app.com, got %q", r0.Hostname)
	}
	if r0.SessionName != "admin" {
		t.Errorf("expected session_name=admin, got %q", r0.SessionName)
	}
	if r0.SessionRole != "primary" {
		t.Errorf("expected role=primary, got %q", r0.SessionRole)
	}
	if r0.Position != 0 {
		t.Errorf("expected position=0, got %d", r0.Position)
	}
	if r0.Headers["X-API-Key"] != "key123" {
		t.Errorf("expected X-API-Key header, got %v", r0.Headers)
	}
	if r0.LoginURL != "" {
		t.Error("expected empty login_url for static-header session")
	}
	if r0.Source != "agent-swarm" {
		t.Errorf("expected source=agent-swarm, got %q", r0.Source)
	}

	// Second row: login flow
	r1 := rows[1]
	if r1.SessionName != "user" {
		t.Errorf("expected session_name=user, got %q", r1.SessionName)
	}
	if r1.Position != 1 {
		t.Errorf("expected position=1, got %d", r1.Position)
	}
	if r1.LoginURL != "https://app.com/api/login" {
		t.Errorf("unexpected login_url: %q", r1.LoginURL)
	}
	if r1.LoginMethod != "POST" {
		t.Errorf("unexpected login_method: %q", r1.LoginMethod)
	}
	if r1.LoginContentType != "application/json" {
		t.Errorf("unexpected login_content_type: %q", r1.LoginContentType)
	}

	// Verify extract rules marshaled as JSON
	if r1.ExtractRules == "" {
		t.Fatal("expected non-empty extract_rules")
	}
	var rules []agenttypes.AgentExtractRule
	if err := json.Unmarshal([]byte(r1.ExtractRules), &rules); err != nil {
		t.Fatalf("failed to unmarshal extract_rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 extract rules, got %d", len(rules))
	}
	if rules[0].Source != "json" || rules[0].Path != "$.access_token" {
		t.Errorf("unexpected first rule: %+v", rules[0])
	}
	if rules[1].Source != "cookie" || rules[1].Name != "sid" {
		t.Errorf("unexpected second rule: %+v", rules[1])
	}
}

func TestAuthHeadersFromAuthenticationHostnames(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		got := AuthHeadersFromAuthenticationHostnames(nil)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		got := AuthHeadersFromAuthenticationHostnames([]*database.AuthenticationHostname{})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("all rows have empty headers", func(t *testing.T) {
		rows := []*database.AuthenticationHostname{
			{SessionRole: "primary", Headers: nil},
			{SessionRole: "compare", Headers: map[string]string{}},
		}
		got := AuthHeadersFromAuthenticationHostnames(rows)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("primary role preferred", func(t *testing.T) {
		rows := []*database.AuthenticationHostname{
			{SessionRole: "compare", Headers: map[string]string{"X-User": "user-tok"}},
			{SessionRole: "primary", Headers: map[string]string{"X-Admin": "admin-tok"}},
		}
		got := AuthHeadersFromAuthenticationHostnames(rows)
		if got == nil {
			t.Fatal("expected non-nil")
		}
		if got["X-Admin"] != "admin-tok" {
			t.Errorf("expected primary headers, got %v", got)
		}
		if _, exists := got["X-User"]; exists {
			t.Error("should not include compare headers")
		}
	})

	t.Run("fallback to first with headers", func(t *testing.T) {
		rows := []*database.AuthenticationHostname{
			{SessionRole: "primary", Headers: nil},
			{SessionRole: "compare", Headers: map[string]string{"Authorization": "Bearer tok"}},
			{SessionRole: "", Headers: map[string]string{"Cookie": "sid=abc"}},
		}
		got := AuthHeadersFromAuthenticationHostnames(rows)
		if got == nil {
			t.Fatal("expected non-nil")
		}
		if got["Authorization"] != "Bearer tok" {
			t.Errorf("expected first non-empty headers, got %v", got)
		}
	})
}

func TestAgentSessionConfigToAuthenticationHostnames_Nil(t *testing.T) {
	rows := AgentSessionConfigToAuthenticationHostnames(nil, "", "", "", "")
	if rows != nil {
		t.Error("expected nil for nil config")
	}

	rows = AgentSessionConfigToAuthenticationHostnames(&agenttypes.AgentSessionConfig{}, "", "", "", "")
	if rows != nil {
		t.Error("expected nil for empty sessions")
	}
}

func TestReplaceAuthHeadersInRecords(t *testing.T) {
	t.Run("nil session headers returns unchanged", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{Method: "GET", URL: "http://example.com", Headers: map[string]string{"Authorization": "Bearer stale"}},
		}
		got := ReplaceAuthHeadersInRecords(records, nil)
		if got[0].Headers["Authorization"] != "Bearer stale" {
			t.Errorf("expected unchanged, got %v", got[0].Headers)
		}
	})

	t.Run("empty session headers returns unchanged", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{Method: "GET", URL: "http://example.com", Headers: map[string]string{"Authorization": "Bearer stale"}},
		}
		got := ReplaceAuthHeadersInRecords(records, map[string]string{})
		if got[0].Headers["Authorization"] != "Bearer stale" {
			t.Errorf("expected unchanged, got %v", got[0].Headers)
		}
	})

	t.Run("session headers without auth keys returns unchanged", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{Method: "GET", URL: "http://example.com", Headers: map[string]string{"Authorization": "Bearer stale"}},
		}
		got := ReplaceAuthHeadersInRecords(records, map[string]string{"X-Custom": "val"})
		if got[0].Headers["Authorization"] != "Bearer stale" {
			t.Errorf("expected unchanged, got %v", got[0].Headers)
		}
	})

	t.Run("replaces Authorization header", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{
				Method:  "GET",
				URL:     "http://example.com/api",
				Headers: map[string]string{"Authorization": "Bearer placeholder", "Content-Type": "application/json"},
			},
		}
		sessionHeaders := map[string]string{"Authorization": "Bearer real-token"}
		got := ReplaceAuthHeadersInRecords(records, sessionHeaders)
		if got[0].Headers["Authorization"] != "Bearer real-token" {
			t.Errorf("expected replaced auth, got %v", got[0].Headers)
		}
		if got[0].Headers["Content-Type"] != "application/json" {
			t.Errorf("expected Content-Type preserved, got %v", got[0].Headers)
		}
	})

	t.Run("replaces Cookie header", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{
				Method:  "GET",
				URL:     "http://example.com",
				Headers: map[string]string{"Cookie": "sid=old"},
			},
		}
		sessionHeaders := map[string]string{"Cookie": "sid=fresh"}
		got := ReplaceAuthHeadersInRecords(records, sessionHeaders)
		if got[0].Headers["Cookie"] != "sid=fresh" {
			t.Errorf("expected replaced cookie, got %v", got[0].Headers)
		}
	})

	t.Run("replaces both Authorization and Cookie", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{
				Method:  "POST",
				URL:     "http://example.com",
				Headers: map[string]string{"Authorization": "Bearer old", "Cookie": "sid=old", "Accept": "*/*"},
			},
		}
		sessionHeaders := map[string]string{"Authorization": "Bearer new", "Cookie": "sid=new"}
		got := ReplaceAuthHeadersInRecords(records, sessionHeaders)
		if got[0].Headers["Authorization"] != "Bearer new" {
			t.Errorf("expected replaced auth, got %v", got[0].Headers)
		}
		if got[0].Headers["Cookie"] != "sid=new" {
			t.Errorf("expected replaced cookie, got %v", got[0].Headers)
		}
		if got[0].Headers["Accept"] != "*/*" {
			t.Errorf("expected Accept preserved, got %v", got[0].Headers)
		}
	})

	t.Run("skips records without auth headers", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{Method: "GET", URL: "http://example.com", Headers: map[string]string{"Accept": "text/html"}},
			{Method: "POST", URL: "http://example.com/api", Headers: map[string]string{"Authorization": "Bearer old"}},
		}
		sessionHeaders := map[string]string{"Authorization": "Bearer new"}
		got := ReplaceAuthHeadersInRecords(records, sessionHeaders)
		// First record should be unchanged
		if _, exists := got[0].Headers["Authorization"]; exists {
			t.Error("first record should not have Authorization added")
		}
		// Second record should be replaced
		if got[1].Headers["Authorization"] != "Bearer new" {
			t.Errorf("expected replaced auth, got %v", got[1].Headers)
		}
	})

	t.Run("skips records with nil headers", func(t *testing.T) {
		records := []agenttypes.AgentHTTPRecord{
			{Method: "GET", URL: "http://example.com"},
		}
		sessionHeaders := map[string]string{"Authorization": "Bearer new"}
		got := ReplaceAuthHeadersInRecords(records, sessionHeaders)
		if got[0].Headers != nil {
			t.Errorf("expected nil headers unchanged, got %v", got[0].Headers)
		}
	})
}
