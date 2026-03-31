package agent

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/backend"
)

func TestMergeSwarmPlansWithQuickChecksAndSnippets(t *testing.T) {
	plans := []*SwarmPlan{
		{
			ModuleTags: []string{"xss"},
			QuickChecks: []QuickCheck{
				{ID: "check-a", Scan: "per_request", Match: QuickCheckMatch{Status: 200}},
			},
			Snippets: []Snippet{
				{ID: "snip-a", Scan: "per_request", Body: "return null;"},
			},
		},
		{
			ModuleTags: []string{"sqli"},
			QuickChecks: []QuickCheck{
				{ID: "check-a", Scan: "per_host", Match: QuickCheckMatch{Status: 500}}, // overwrites
				{ID: "check-b", Scan: "per_request", Match: QuickCheckMatch{BodyContains: "x"}},
			},
			Snippets: []Snippet{
				{ID: "snip-b", Scan: "per_request", Body: "return [];"},
			},
		},
	}

	merged, _ := mergeSwarmPlans(plans)

	if len(merged.ModuleTags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(merged.ModuleTags))
	}

	// check-a should be last-wins (per_host from plan 2)
	if len(merged.QuickChecks) != 2 {
		t.Errorf("expected 2 quick_checks (deduplicated), got %d", len(merged.QuickChecks))
	}

	if len(merged.Snippets) != 2 {
		t.Errorf("expected 2 snippets, got %d", len(merged.Snippets))
	}

	// Verify last-wins for check-a
	for _, qc := range merged.QuickChecks {
		if qc.ID == "check-a" && qc.Scan != "per_host" {
			t.Errorf("expected check-a to be overwritten to per_host, got %q", qc.Scan)
		}
	}
}

func TestNormalizePlan(t *testing.T) {
	plan := &SwarmPlan{
		ModuleTags: []string{"SQLI", "xss (common in login)", "auth - important", "sqli"},
		ModuleIDs:  []string{"sqli-error-based", "SQLI-ERROR-BASED", "xss-reflected (DOM)"},
		FocusAreas: []string{" SQL injection in login ", "SQL injection in login", "  "},
	}

	normalizePlan(plan)

	// Tags should be lowered, deduped, commentary stripped
	expectedTags := []string{"sqli", "xss", "auth"}
	if len(plan.ModuleTags) != len(expectedTags) {
		t.Fatalf("expected %d tags, got %d: %v", len(expectedTags), len(plan.ModuleTags), plan.ModuleTags)
	}
	for i, tag := range expectedTags {
		if plan.ModuleTags[i] != tag {
			t.Errorf("tag[%d]: expected %q, got %q", i, tag, plan.ModuleTags[i])
		}
	}

	// IDs should be lowered, deduped, commentary stripped
	expectedIDs := []string{"sqli-error-based", "xss-reflected"}
	if len(plan.ModuleIDs) != len(expectedIDs) {
		t.Fatalf("expected %d IDs, got %d: %v", len(expectedIDs), len(plan.ModuleIDs), plan.ModuleIDs)
	}
	for i, id := range expectedIDs {
		if plan.ModuleIDs[i] != id {
			t.Errorf("id[%d]: expected %q, got %q", i, id, plan.ModuleIDs[i])
		}
	}

	// Focus areas should be trimmed, deduped, empty removed
	if len(plan.FocusAreas) != 1 {
		t.Fatalf("expected 1 focus area, got %d: %v", len(plan.FocusAreas), plan.FocusAreas)
	}
	if plan.FocusAreas[0] != "SQL injection in login" {
		t.Errorf("expected 'SQL injection in login', got %q", plan.FocusAreas[0])
	}
}

func TestSessionConfigToHTTPRecords(t *testing.T) {
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
				},
			},
			{
				Name:    "api_key_user",
				Role:    "primary",
				Headers: map[string]string{"Authorization": "Bearer static-token"},
				// No login flow — should not produce a record
			},
		},
	}

	records := backend.SessionConfigToHTTPRecords(cfg)

	// Two sessions share the same login URL+method, so should be deduplicated to 1
	if len(records) != 1 {
		t.Fatalf("expected 1 deduplicated record, got %d", len(records))
	}
	if records[0].Method != "POST" {
		t.Errorf("expected POST, got %q", records[0].Method)
	}
	if records[0].URL != "http://localhost:3000/rest/user/login" {
		t.Errorf("unexpected URL: %s", records[0].URL)
	}
	if records[0].Headers["Content-Type"] != "application/json" {
		t.Errorf("expected Content-Type header, got %v", records[0].Headers)
	}
}

func TestSessionConfigToHTTPRecords_DifferentURLs(t *testing.T) {
	cfg := &AgentSessionConfig{
		Sessions: []AgentSessionEntry{
			{
				Name: "admin",
				Login: &AgentLoginFlow{
					URL:    "http://localhost:3000/api/admin/login",
					Method: "POST",
					Body:   `{"username":"admin"}`,
				},
			},
			{
				Name: "user",
				Login: &AgentLoginFlow{
					URL:    "http://localhost:3000/api/user/login",
					Method: "POST",
					Body:   `{"username":"user"}`,
				},
			},
		},
	}

	records := backend.SessionConfigToHTTPRecords(cfg)
	if len(records) != 2 {
		t.Fatalf("expected 2 records for different login URLs, got %d", len(records))
	}
}

func TestSessionConfigToHTTPRecords_Nil(t *testing.T) {
	if records := backend.SessionConfigToHTTPRecords(nil); records != nil {
		t.Errorf("expected nil for nil config, got %v", records)
	}
	if records := backend.SessionConfigToHTTPRecords(&AgentSessionConfig{}); records != nil {
		t.Errorf("expected nil for empty sessions, got %v", records)
	}
}

func TestBuildSessionConfigRepairPrompt(t *testing.T) {
	garbled := `{"sessions":[{"name":"admin","login":{"url":"http://example.com/login","extract":[{"source":"json"`
	prompt := buildSessionConfigRepairPrompt(garbled)

	checks := []struct {
		name    string
		keyword string
	}{
		{"contains schema", `"sessions"`},
		{"contains extract in schema", `"extract"`},
		{"contains apply_as in schema", `"apply_as"`},
		{"contains garbled output", garbled},
		{"mentions extract critical", "CRITICAL"},
		{"mentions fix JSON", "Fix the JSON"},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(prompt, c.keyword) {
				t.Errorf("prompt missing expected keyword %q", c.keyword)
			}
		})
	}
}
