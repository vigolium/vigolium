package agent

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

func TestTryStructuredFallback_URL(t *testing.T) {
	intent := tryStructuredFallback("https://example.com/api/login")
	if intent == nil {
		t.Fatal("expected intent for URL input")
	}
	if len(intent.Apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(intent.Apps))
	}
	if intent.Apps[0].Target != "https://example.com/api/login" {
		t.Errorf("expected target URL, got %q", intent.Apps[0].Target)
	}
}

func TestTryStructuredFallback_NaturalLanguage(t *testing.T) {
	// Natural language should NOT match structured fallback
	intent := tryStructuredFallback("scan the source code from ~/Desktop/demo/VAmPI running on http://localhost:3005")
	if intent != nil {
		t.Error("expected nil for natural language input, got intent")
	}
}

func TestTryStructuredFallback_Curl(t *testing.T) {
	// Curl commands should return nil (handled via normal --input flow, not intent)
	intent := tryStructuredFallback("curl -X POST https://example.com/api")
	if intent != nil {
		t.Error("expected nil for curl input")
	}
}

func TestTryStructuredFallback_Empty(t *testing.T) {
	intent := tryStructuredFallback("")
	if intent != nil {
		t.Error("expected nil for empty input")
	}
}

func TestParseIntentJSON(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantApps int
		wantErr  bool
	}{
		{
			name: "simple JSON",
			raw: `{
				"apps": [
					{
						"target": "http://localhost:3005",
						"source_path": "~/Desktop/demo/VAmPI",
						"discover": true
					}
				]
			}`,
			wantApps: 1,
		},
		{
			name: "JSON in markdown fences",
			raw: "```json\n" + `{"apps": [{"target": "http://localhost:3005", "source_path": "/src/app"}]}` + "\n```",
			wantApps: 1,
		},
		{
			name: "multi-app",
			raw: `{
				"apps": [
					{"source_path": "~/Desktop/demo/crAPI", "code_audit": true},
					{"source_path": "~/Desktop/demo/DVWA", "code_audit": true}
				]
			}`,
			wantApps: 2,
		},
		{
			name:    "empty response",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "no JSON in response",
			raw:     "I don't understand the request",
			wantErr: true,
		},
		{
			name:     "empty apps array",
			raw:      `{"apps": []}`,
			wantApps: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intent, err := parseIntentJSON(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(intent.Apps) != tt.wantApps {
				t.Errorf("expected %d apps, got %d", tt.wantApps, len(intent.Apps))
			}
		})
	}
}

func TestExpandHome(t *testing.T) {
	tests := []struct {
		input string
		home  bool // whether result should start with /
	}{
		{"~/Desktop/demo", true},
		{"/absolute/path", true},
		{"relative/path", false},
		{"", false},
	}

	for _, tt := range tests {
		result := agenttypes.ExpandHome(tt.input)
		if tt.home && tt.input != "" && result[0] != '/' {
			t.Errorf("ExpandHome(%q) = %q, expected absolute path", tt.input, result)
		}
		if tt.input == "" && result != "" {
			t.Errorf("ExpandHome(\"\") = %q, expected empty", result)
		}
	}
}

func TestResolveIntentApps(t *testing.T) {
	t.Run("source with target sets discover", func(t *testing.T) {
		intent := &ScanIntent{
			Apps: []AppIntent{
				{Target: "http://localhost:3005", SourcePath: "/src/app"},
			},
		}
		resolved := ResolveIntentApps(intent)
		if !resolved.Apps[0].Discover {
			t.Error("expected discover=true when both target and source are set")
		}
	})

	t.Run("source without target sets code_audit", func(t *testing.T) {
		intent := &ScanIntent{
			Apps: []AppIntent{
				{SourcePath: "/nonexistent/path"},
			},
		}
		resolved := ResolveIntentApps(intent)
		if !resolved.Apps[0].CodeAudit {
			t.Error("expected code_audit=true when source-only")
		}
	})
}

func TestParseAndResolveIntent_EmptyApps(t *testing.T) {
	// ParseAndResolveIntent should return error for empty apps
	// (Can't fully test without an engine, but we test the structural flow via parseIntentJSON)
	intent, err := parseIntentJSON(`{"apps": []}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(intent.Apps) != 0 {
		t.Error("expected 0 apps")
	}
}
