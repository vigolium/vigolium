package agent

import (
	"strings"
	"testing"
)

func TestValidateSessionConfig_ValidEntries(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "admin",
				Role: "primary",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"email":"admin@juice-sh.op","password":"admin123"}`,
					Extract:     []AgentExtractRule{{Source: "json", Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}},
				},
			},
			{
				Name: "regular_user",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"email":"jim@juice-sh.op","password":"ncc-1701"}`,
					Extract:     []AgentExtractRule{{Source: "json", Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}},
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Sessions) != 2 {
		t.Fatalf("expected 2 valid sessions, got %d", len(result.Sessions))
	}
}

func TestValidateSessionConfig_DropsGarbledRole(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "admin",
				Role: "primary",
				Login: &AgentLoginFlow{
					URL:     "http://localhost:3000/rest/user/login",
					Method:  "POST",
					Extract: []AgentExtractRule{{Source: "cookie", Name: "session"}},
				},
			},
			{
				Name: "support_admin",
				Role: "comparelocalhost:3000/rest/user", // garbled
				Login: &AgentLoginFlow{
					URL:     "http://localhost:3000/rest/user/login",
					Method:  "POST",
					Extract: []AgentExtractRule{{Source: "cookie", Name: "session"}},
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result (admin should survive)")
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 valid session, got %d", len(result.Sessions))
	}
	if result.Sessions[0].Name != "admin" {
		t.Errorf("expected admin session, got %s", result.Sessions[0].Name)
	}
}

func TestValidateSessionConfig_DropsLoginWithoutExtractRules(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "deluser",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"email":"bjoern@owasp.org","password":"test"}`,
					// no extract rules — downstream session.Validate() would reject this
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (no extract rules), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_DropsEmptyRole(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "account",
				Role: "", // empty
				Login: &AgentLoginFlow{
					URL:    "http://localhost:3000/rest/user/login",
					Method: "POST",
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (empty role), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_DropsInvalidURL(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "demo",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:    "http:///login", // no host
					Method: "POST",
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (all invalid), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_DropsURLWithoutPath(t *testing.T) {
	// URL is just host:port — the login path got truncated
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "deluser",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"email":"bjoern@owasp.org","password":"test"}`,
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (URL without path), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_DropsGarbledContentTypeNonJSON(t *testing.T) {
	// content_type has URL path leaked into it AND body is not JSON
	// so it can't be auto-fixed
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "regular",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/rest/user/login", // garbled
					Body:        "not json body",
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (garbled content_type), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_FixesGarbledContentTypeWithJSONBody(t *testing.T) {
	// content_type is garbled but body is valid JSON — sanitizer auto-fixes
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "regular",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/rest/user/login", // garbled
					Body:        `{"email":"jim@juice-sh.op","password":"ncc-1701"}`,
					Extract:     []AgentExtractRule{{Source: "json", Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}},
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result (content_type should be auto-fixed)")
	}
	if result.Sessions[0].Login.ContentType != "application/json" {
		t.Errorf("expected content_type fixed to application/json, got: %s",
			result.Sessions[0].Login.ContentType)
	}
}

func TestValidateSessionConfig_DropsInvalidJSONBody(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "customer",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"email":"jim@juice-sh.op","password":"ncc-1701`, // truncated
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (invalid JSON body), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_DropsGarbledBodyFieldNames(t *testing.T) {
	// Body has garbled field name: "email@juice" instead of "email"
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "regular",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{"email@juice":"jim-sh.op","password":"ncc1701"}`,
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil result (garbled body field), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_FixesDoubleEscapedBody(t *testing.T) {
	// Body has double-escaped JSON: \\\" instead of \"
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "admin",
				Role: "primary",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{\\\"email\\\":\\\"admin@juice-sh.op\\\",\\\"password\\\":\\\"admin123\\\"}`,
					Extract:     []AgentExtractRule{{Source: "json", Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}},
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result after double-escape fix")
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result.Sessions))
	}
	// Verify body was fully unescaped to valid JSON
	body := result.Sessions[0].Login.Body
	if body != `{"email":"admin@juice-sh.op","password":"admin123"}` {
		t.Errorf("expected fully unescaped JSON body, got: %s", body)
	}
}

func TestValidateSessionConfig_FixesGarbledContentType(t *testing.T) {
	// content_type is garbled but body is valid JSON — should auto-fix to application/json
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "user",
				Role: "primary",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/rest/user/login",
					Body:        `{"email":"test@test.com","password":"test"}`,
					Extract:     []AgentExtractRule{{Source: "json", Path: "$.token", ApplyAs: "Authorization: Bearer {value}"}},
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result after content_type fix")
	}
	if result.Sessions[0].Login.ContentType != "application/json" {
		t.Errorf("expected content_type fixed to application/json, got: %s",
			result.Sessions[0].Login.ContentType)
	}
}

func TestValidateSessionConfig_AllowsStaticHeaders(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name:    "api_client",
				Role:    "primary",
				Headers: map[string]string{"X-API-Key": "abc123"},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result.Sessions))
	}
}

func TestValidateSessionConfig_NilAndEmpty(t *testing.T) {
	if result := ValidateSessionConfig(nil); result != nil {
		t.Error("expected nil for nil input")
	}

	empty := &AgentSessionConfig{}
	if result := ValidateSessionConfig(empty); result != empty {
		t.Error("expected same pointer back for empty sessions")
	}
}

func TestValidateSessionConfig_DropsNoAuthEntry(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "noauth",
				Role: "primary",
				// no login, no headers
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result != nil {
		t.Fatalf("expected nil (no auth), got %d sessions", len(result.Sessions))
	}
}

func TestValidateSessionConfig_NonJSONBodyAllowed(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "form_login",
				Role: "primary",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/login",
					Method:      "POST",
					ContentType: "application/x-www-form-urlencoded",
					Body:        "username=admin&password=admin123",
					Extract:     []AgentExtractRule{{Source: "cookie", Name: "session_id"}},
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	if result == nil {
		t.Fatal("expected non-nil result for form-encoded body")
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result.Sessions))
	}
}

func TestValidateSessionConfig_RealWorldGarbled(t *testing.T) {
	// Full real-world example from user report
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "account",
				Role: "", // empty
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000/rest/user/login",
					Method:      "POST",
					ContentType: "application/json",
					Body:        `{\\\"email\\\":\\\"accountant@juice-sh.op\\\",\\\"password\\\":\\\"i am an awesome accountant\\\"}`,
				},
			},
			{
				Name: "deluser",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000", // missing path
					Method:      "POST",
					ContentType: "application/rest/user/login", // garbled
					Body:        `{\\\"email\\\":\\\"bjoern@owasp.org\\\",\\\"password\\\":\\\"kitten lesseroch ka porate buffoonoors\\\"}`,
				},
			},
			{
				Name: "regular",
				Role: "compare",
				Login: &AgentLoginFlow{
					URL:         "http://localhost:3000", // missing path
					Method:      "POST",
					ContentType: "application/rest/user/login", // garbled
					Body:        `{\\\"email@juice\\\":\\\"jim-sh.op\\\",\\\"password\\\":\\\"ncc1701\\\"}`,
				},
			},
		},
	}

	result := ValidateSessionConfig(cfg)
	// All three should be dropped:
	// 1: empty role
	// 2: URL without path
	// 3: URL without path + garbled body field name
	if result != nil {
		for _, s := range result.Sessions {
			t.Errorf("session %q should have been dropped (role=%q url=%q)",
				s.Name, s.Role, s.Login.URL)
		}
		t.Fatalf("expected nil result (all garbled), got %d sessions", len(result.Sessions))
	}
}

func TestBuildSessionRepairPrompt(t *testing.T) {
	garbledJSON := `{
  "sessions": [
    {
      "name": "account",
      "role": "",
      "login": {
        "url": "http://localhost:3000/rest/user/login",
        "method": "POST"
      }
    }
  ]
}`
	errors := []string{
		`  Session "account": role must be "primary" or "compare", got: ""`,
	}

	prompt := buildSessionRepairPrompt(garbledJSON, errors, "http://localhost:3000")
	if !strings.Contains(prompt, "REGENERATE") && !strings.Contains(prompt, "Fix") {
		t.Error("prompt should contain fix/repair instruction")
	}
	if !strings.Contains(prompt, "http://localhost:3000") {
		t.Error("prompt should include target URL")
	}
	if !strings.Contains(prompt, `"account"`) {
		t.Error("prompt should include garbled JSON")
	}
	if !strings.Contains(prompt, "role") {
		t.Error("prompt should mention role validation error")
	}
}

func TestParseRepairedSessionConfig(t *testing.T) {
	raw := `Here's the fixed config:

` + "```json" + `
{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "login": {
        "url": "http://localhost:3000/rest/user/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}"
      }
    }
  ]
}
` + "```"

	result := parseRepairedSessionConfig(raw)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(result.Sessions))
	}
	if result.Sessions[0].Role != "primary" {
		t.Errorf("expected primary role, got %s", result.Sessions[0].Role)
	}
}

func TestIsValidContentType(t *testing.T) {
	valid := []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain",
		"application/xml",
		"text/html",
	}
	for _, ct := range valid {
		if !isValidContentType(ct) {
			t.Errorf("expected %q to be valid", ct)
		}
	}

	invalid := []string{
		"application/rest/user/login",
		"application/api/v1/auth",
		"text/html/login/page",
	}
	for _, ct := range invalid {
		if isValidContentType(ct) {
			t.Errorf("expected %q to be invalid", ct)
		}
	}
}
