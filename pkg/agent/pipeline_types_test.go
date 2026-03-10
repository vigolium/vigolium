package agent

import (
	"testing"
)

func TestParseSwarmPlan(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		tags    int
		exts    int
	}{
		{
			name: "direct format",
			input: `{
				"module_tags": ["sqli", "xss"],
				"module_ids": ["sqli-error-based"],
				"extensions": [
					{
						"filename": "custom-check.js",
						"code": "var module = {};",
						"reason": "test"
					}
				],
				"focus_areas": ["SQL injection"],
				"notes": "test plan"
			}`,
			wantErr: false,
			tags:    2,
			exts:    1,
		},
		{
			name: "wrapped format",
			input: `{
				"swarm_plan": {
					"module_tags": ["injection"],
					"focus_areas": ["auth bypass"]
				}
			}`,
			wantErr: false,
			tags:    1,
			exts:    0,
		},
		{
			name:    "with markdown fences",
			input:   "Here is the plan:\n```json\n{\"module_tags\": [\"xss\", \"sqli\"]}\n```\n",
			wantErr: false,
			tags:    2,
			exts:    0,
		},
		{
			name:    "no module tags",
			input:   `{"focus_areas": ["test"]}`,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name: "hybrid format - plan JSON plus code blocks",
			input: `Here is my analysis:

{"module_tags":["sqli","xss","ssti"],"module_ids":["sqli-error-based","xss-light-url-params"],"focus_areas":["SQL injection in q parameter"],"notes":"Juice Shop SQLite target"}

#### custom-sqli-search.js
Reason: Custom SQLi payloads for SQLite

` + "```javascript" + `
var module = {
    id: "custom-sqli-search",
    name: "Custom SQLi Search",
    severity: "critical",
    confidence: "tentative",
    tags: ["custom", "sqli"],
    scan_types: ["per_request"]
};

function scan_per_request(ctx) {
    return [];
}
` + "```" + `

#### custom-jwt-check.js
Reason: JWT algorithm confusion test

` + "```javascript" + `
var module = {
    id: "custom-jwt-check",
    name: "JWT Check",
    severity: "high",
    confidence: "tentative",
    tags: ["custom", "auth"],
    scan_types: ["per_request"]
};

function scan_per_request(ctx) {
    return [];
}
` + "```" + `
`,
			wantErr: false,
			tags:    3,
			exts:    2,
		},
		{
			name: "hybrid format - no heading, extracts filename from code",
			input: `{"module_tags":["xss"],"focus_areas":["reflected xss"]}

` + "```javascript" + `
var module = {
    id: "custom-reflected-xss",
    name: "Reflected XSS",
    severity: "high",
    confidence: "tentative",
    tags: ["custom"],
    scan_types: ["per_request"]
};

function scan_per_request(ctx) {
    return [];
}
` + "```" + `
`,
			wantErr: false,
			tags:    1,
			exts:    1,
		},
		{
			name: "hybrid format - plan only, no extensions",
			input: `{"module_tags":["injection","cors"],"module_ids":[],"focus_areas":["CORS misconfiguration"],"notes":"simple scan"}
`,
			wantErr: false,
			tags:    2,
			exts:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := ParseSwarmPlan(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(plan.ModuleTags) != tt.tags {
				t.Errorf("expected %d tags, got %d: %v", tt.tags, len(plan.ModuleTags), plan.ModuleTags)
			}
			if len(plan.Extensions) != tt.exts {
				t.Errorf("expected %d extensions, got %d", tt.exts, len(plan.Extensions))
			}
		})
	}
}

func TestParseSwarmPlanHybridExtensionMeta(t *testing.T) {
	input := `{"module_tags":["sqli"],"focus_areas":["test"]}

#### custom-sqli-union.js
Reason: UNION-based SQLi for SQLite

` + "```javascript" + `
var module = {
    id: "custom-sqli-union",
    name: "SQLi UNION",
    severity: "critical",
    confidence: "tentative",
    tags: ["custom"],
    scan_types: ["per_request"]
};

function scan_per_request(ctx) { return []; }
` + "```" + `
`

	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plan.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(plan.Extensions))
	}

	ext := plan.Extensions[0]
	if ext.Filename != "custom-sqli-union.js" {
		t.Errorf("expected filename 'custom-sqli-union.js', got %q", ext.Filename)
	}
	if ext.Reason != "UNION-based SQLi for SQLite" {
		t.Errorf("expected reason 'UNION-based SQLi for SQLite', got %q", ext.Reason)
	}
	if ext.Code == "" {
		t.Error("expected non-empty code")
	}
}
