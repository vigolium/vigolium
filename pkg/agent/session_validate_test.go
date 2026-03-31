package agent

import (
	"strings"
	"testing"
)

// TestBuildSessionRepairPrompt stays in the root agent package because it
// calls buildSessionRepairPrompt which lives in session_repair.go (not in backend).
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

	prompt := buildSessionRepairPrompt(garbledJSON, errors, "http://localhost:3000", "")
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

// TestParseRepairedSessionConfig stays in the root agent package because it
// calls parseRepairedSessionConfig which lives in session_repair.go (not in backend).
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
