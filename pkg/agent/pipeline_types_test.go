package agent

import (
	"strings"
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
			name:    "no module tags but has focus areas",
			input:   `{"focus_areas": ["test"]}`,
			wantErr: false,
			tags:    0,
			exts:    0,
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

func TestParseSwarmPlanCorruptedFirstValidSecond(t *testing.T) {
	// First JSON block is corrupted/garbled, but a valid plan block follows
	input := `Here is the analysis:

{"module_tags": ["sqli"], "extensions": [{"filename": "check.js", "code": "var x = function() { return \"broken
json string with unescaped stuff"}]}

Actually, here is the corrected plan:

{"module_tags":["sqli","xss"],"focus_areas":["SQL injection"],"notes":"corrected"}
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 2 {
		t.Errorf("expected 2 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
}

func TestParseSwarmPlanMultiLineJSON(t *testing.T) {
	// Plan JSON is formatted across multiple lines (not single-line)
	input := `Here is the plan:

{
  "module_tags": ["injection", "auth"],
  "module_ids": ["sqli-error-based"],
  "focus_areas": ["authentication bypass"],
  "notes": "multi-line formatted"
}
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 2 {
		t.Errorf("expected 2 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
	if plan.Notes != "multi-line formatted" {
		t.Errorf("expected notes 'multi-line formatted', got %q", plan.Notes)
	}
}

func TestParseSwarmPlanGarbledJSONRegexFallback(t *testing.T) {
	// Real-world garbled output: module_tags array is clean but quick_checks has broken JSON
	// This simulates the actual corruption pattern seen in production LLM output
	input := `## Analysis

**Request:** A simple GET request to the root.

` + "```" + `
{"module_tags":["discovery","fingerprint","header-security","misconfiguration","sensitive-file","xss","injection"],"module_ids":[],"quick_checks":[{"id":"sensitive-files","severity-node":"high","scan":"per_host","requests":[{"method":"GET","path":"/.env"},{"method":"GET","path":"/package.json"}],"match":{"status":200,"body_regex":"(DB_|SECRET|password|token|mongodb|mysql)"}},{"id":"express-errors","severity":"low","scan":"per_host","requests":"/non":[{"method":"GET","pathexistent-path"}],"match":{"body_regex":"(Cannot GET|at\\sLayer)"}}],"focus_areas":["Technology stack fingerprinting","Sensitive file exposure"],"notes":"Broad recon scan for port 3000"}
` + "```" + `
`

	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error (regex fallback should recover module_tags): %v", err)
	}
	if len(plan.ModuleTags) != 7 {
		t.Errorf("expected 7 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
	if len(plan.FocusAreas) != 2 {
		t.Errorf("expected 2 focus_areas, got %d: %v", len(plan.FocusAreas), plan.FocusAreas)
	}
}

func TestParseSwarmPlanJSONInFencedBlock(t *testing.T) {
	// JSON is inside a markdown code fence but with surrounding text
	input := `Here is my scan plan:

` + "```json" + `
{"module_tags":["sqli","xss"],"focus_areas":["SQL injection"],"notes":"test"}
` + "```" + `

The above plan targets SQL injection.`

	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 2 {
		t.Errorf("expected 2 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
}

func TestParseSwarmPlanWithQuickChecks(t *testing.T) {
	input := `{"module_tags":["injection"],"quick_checks":[{"id":"ssti-check","scan":"per_insertion_point","severity":"high","payloads":["{{7*7}}"],"match":{"body_contains":"49"}}],"focus_areas":["SSTI"]}`

	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plan.QuickChecks) != 1 {
		t.Fatalf("expected 1 quick_check, got %d", len(plan.QuickChecks))
	}

	qc := plan.QuickChecks[0]
	if qc.ID != "ssti-check" {
		t.Errorf("expected id 'ssti-check', got %q", qc.ID)
	}
	if qc.Scan != "per_insertion_point" {
		t.Errorf("expected scan 'per_insertion_point', got %q", qc.Scan)
	}
	if len(qc.Payloads) != 1 {
		t.Errorf("expected 1 payload, got %d", len(qc.Payloads))
	}
	if qc.Match.BodyContains != "49" {
		t.Errorf("expected body_contains '49', got %q", qc.Match.BodyContains)
	}
}

func TestParseSwarmPlanWithSnippets(t *testing.T) {
	input := `{"module_tags":["xss"],"snippets":[{"id":"custom-check","scan":"per_request","body":"return null;"}]}`

	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plan.Snippets) != 1 {
		t.Fatalf("expected 1 snippet, got %d", len(plan.Snippets))
	}

	snip := plan.Snippets[0]
	if snip.ID != "custom-check" {
		t.Errorf("expected id 'custom-check', got %q", snip.ID)
	}
	if snip.Body != "return null;" {
		t.Errorf("expected body 'return null;', got %q", snip.Body)
	}
}

func TestParseSwarmPlanHybridWithQuickChecksAndExtensions(t *testing.T) {
	input := `{"module_tags":["sqli"],"quick_checks":[{"id":"sqli-time","scan":"per_insertion_point","payloads":["1 AND SLEEP(5)"],"match":{"status":200}}],"snippets":[{"id":"header-check","scan":"per_request","body":"return null;"}]}

#### custom-deep-check.js
Reason: Deep SQLi check

` + "```javascript" + `
module.exports = {
    id: "custom-deep-check",
    type: "active",
    scanTypes: ["per_request"],
    scanPerRequest: function(ctx) { return null; }
};
` + "```" + `
`

	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plan.QuickChecks) != 1 {
		t.Errorf("expected 1 quick_check, got %d", len(plan.QuickChecks))
	}
	if len(plan.Snippets) != 1 {
		t.Errorf("expected 1 snippet, got %d", len(plan.Snippets))
	}
	if len(plan.Extensions) != 1 {
		t.Errorf("expected 1 extension, got %d", len(plan.Extensions))
	}
}

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

func TestParseSwarmPlanMarkdownBasic(t *testing.T) {
	input := `I analyzed the request and here is my plan:

## MODULE_TAGS
sqli, xss, injection, auth

## MODULE_IDS
sqli-error-based, xss-reflected

## FOCUS_AREAS
- SQL injection in login parameter
- XSS in search results page
- CORS misconfiguration

## NOTES
Target appears to be Express.js on port 3000. No auth headers present.
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 4 {
		t.Errorf("expected 4 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
	if plan.ModuleTags[0] != "sqli" || plan.ModuleTags[3] != "auth" {
		t.Errorf("unexpected tags: %v", plan.ModuleTags)
	}
	if len(plan.ModuleIDs) != 2 {
		t.Errorf("expected 2 module IDs, got %d: %v", len(plan.ModuleIDs), plan.ModuleIDs)
	}
	if len(plan.FocusAreas) != 3 {
		t.Errorf("expected 3 focus areas, got %d: %v", len(plan.FocusAreas), plan.FocusAreas)
	}
	if plan.Notes == "" {
		t.Error("expected non-empty notes")
	}
}

func TestParseSwarmPlanMarkdownMinimal(t *testing.T) {
	// Only the required section
	input := `## MODULE_TAGS
discovery, fingerprint, light
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 3 {
		t.Errorf("expected 3 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
	if len(plan.ModuleIDs) != 0 {
		t.Errorf("expected 0 module IDs, got %d", len(plan.ModuleIDs))
	}
	if len(plan.FocusAreas) != 0 {
		t.Errorf("expected 0 focus areas, got %d", len(plan.FocusAreas))
	}
}

func TestParseSwarmPlanMarkdownWithExtensions(t *testing.T) {
	input := `## MODULE_TAGS
sqli, xss

## FOCUS_AREAS
- SQL injection in search parameter

#### custom-sqli-check.js
Reason: Custom SQLi payloads for SQLite

` + "```javascript" + `
module.exports = {
    id: "custom-sqli-check",
    name: "Custom SQLi",
    type: "active",
    severity: "high",
    tags: ["custom"],
    scanTypes: ["per_request"],
    scanPerRequest: function(ctx) { return null; }
};
` + "```" + `
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(plan.ModuleTags))
	}
	if len(plan.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(plan.Extensions))
	}
	if plan.Extensions[0].Filename != "custom-sqli-check.js" {
		t.Errorf("expected filename 'custom-sqli-check.js', got %q", plan.Extensions[0].Filename)
	}
	if plan.Extensions[0].Reason != "Custom SQLi payloads for SQLite" {
		t.Errorf("expected reason, got %q", plan.Extensions[0].Reason)
	}
}

func TestParseSwarmPlanMarkdownWithQuickChecks(t *testing.T) {
	input := `## MODULE_TAGS
ssti, injection

## FOCUS_AREAS
- SSTI in template parameters

` + "```json" + `
[{"id":"ssti-check","scan":"per_insertion_point","severity":"high","payloads":["{{7*7}}"],"match":{"body_contains":"49"}}]
` + "```" + `
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(plan.ModuleTags))
	}
	if len(plan.QuickChecks) != 1 {
		t.Fatalf("expected 1 quick check, got %d", len(plan.QuickChecks))
	}
	if plan.QuickChecks[0].ID != "ssti-check" {
		t.Errorf("expected id 'ssti-check', got %q", plan.QuickChecks[0].ID)
	}
}

func TestParseSwarmPlanMarkdownFocusAreasVariants(t *testing.T) {
	// Test with asterisk bullets and plain text
	input := `## MODULE_TAGS
xss

## FOCUS_AREAS
* Reflected XSS in query params
* Stored XSS in comments
DOM-based XSS
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.FocusAreas) != 3 {
		t.Errorf("expected 3 focus areas, got %d: %v", len(plan.FocusAreas), plan.FocusAreas)
	}
}

func TestParseSwarmPlanMarkdownPrecedence(t *testing.T) {
	// Markdown format should be tried first and win over JSON
	input := `## MODULE_TAGS
sqli, xss, auth

## NOTES
This is the markdown format

## MODULE_IDS
sqli-error-based
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Markdown parser should win with 3 tags
	if len(plan.ModuleTags) != 3 {
		t.Errorf("expected 3 tags from markdown format, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
	if plan.Notes != "This is the markdown format" {
		t.Errorf("expected markdown notes, got %q", plan.Notes)
	}
	if len(plan.ModuleIDs) != 1 {
		t.Errorf("expected 1 module ID, got %d", len(plan.ModuleIDs))
	}
}

func TestSplitMarkdownSections(t *testing.T) {
	input := `Some preamble text

## MODULE_TAGS
sqli, xss

## FOCUS_AREAS
- item one
- item two

## NOTES
Some notes here
with multiple lines
`
	sections := splitMarkdownSections(input)

	if _, ok := sections["MODULE_TAGS"]; !ok {
		t.Error("expected MODULE_TAGS section")
	}
	if _, ok := sections["FOCUS_AREAS"]; !ok {
		t.Error("expected FOCUS_AREAS section")
	}
	if _, ok := sections["NOTES"]; !ok {
		t.Error("expected NOTES section")
	}
	// Preamble before first ## should not create a section
	if len(sections) != 3 {
		t.Errorf("expected 3 sections, got %d: %v", len(sections), sections)
	}
}

func TestSplitMarkdownSectionsIgnoresH3(t *testing.T) {
	// ### headings should NOT create new sections (they're subsections)
	input := `## MODULE_TAGS
sqli, xss

### Sub-heading
This is inside MODULE_TAGS section
`
	sections := splitMarkdownSections(input)
	tags := sections["MODULE_TAGS"]
	if tags == "" {
		t.Fatal("expected MODULE_TAGS section")
	}
	// The ### line and content after it should be part of MODULE_TAGS
	if len(sections) != 1 {
		t.Errorf("expected 1 section (### should not split), got %d", len(sections))
	}
}

func TestParseCommaSeparated(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"sqli, xss, injection", 3},
		{"  sqli  ,  xss  ", 2},
		{"single", 1},
		{"", 0},
		{", , ,", 0},
	}
	for _, tt := range tests {
		got := parseCommaSeparated(tt.input)
		if len(got) != tt.want {
			t.Errorf("parseCommaSeparated(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestParseBulletList(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"- item one\n- item two\n- item three", 3},
		{"* item one\n* item two", 2},
		{"- dash\n* star\nplain", 3},
		{"", 0},
		{"\n\n\n", 0},
	}
	for _, tt := range tests {
		got := parseBulletList(tt.input)
		if len(got) != tt.want {
			t.Errorf("parseBulletList(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
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

func TestParseSwarmPlanMarkdownNeedsExtensions(t *testing.T) {
	input := `## MODULE_TAGS
sqli, xss

## FOCUS_AREAS
- SQL injection in login form

## NEEDS_EXTENSIONS
yes

## NOTES
Custom extension needed for non-standard JSON-RPC endpoint.
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.NeedsExtensions {
		t.Error("expected NeedsExtensions to be true")
	}
	if len(plan.ModuleTags) != 2 {
		t.Errorf("expected 2 module tags, got %d", len(plan.ModuleTags))
	}
}

func TestParseSwarmPlanMarkdownNeedsExtensionsNo(t *testing.T) {
	input := `## MODULE_TAGS
sqli, xss

## NEEDS_EXTENSIONS
no
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.NeedsExtensions {
		t.Error("expected NeedsExtensions to be false")
	}
}

func TestParseSwarmExtensions(t *testing.T) {
	input := `Here are the custom extensions:

#### ssti-check.js
Reason: Check for server-side template injection

` + "```javascript\n" + `module.exports = {
  id: "ssti-check",
  name: "SSTI Check",
  type: "active",
  severity: "high",
  confidence: "tentative",
  tags: ["custom"],
  scanTypes: ["per_insertion_point"],
  scanPerInsertionPoint: function(ctx, insertion) {
    return null;
  }
};
` + "```\n"

	plan, err := ParseSwarmExtensions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if len(plan.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(plan.Extensions))
	}
	if plan.Extensions[0].Filename != "ssti-check.js" {
		t.Errorf("expected filename 'ssti-check.js', got %q", plan.Extensions[0].Filename)
	}
	if plan.Extensions[0].Reason != "Check for server-side template injection" {
		t.Errorf("expected reason, got %q", plan.Extensions[0].Reason)
	}
}

func TestParseSwarmExtensionsQuickChecks(t *testing.T) {
	input := "Here are some quick checks:\n\n```json\n" +
		`[{"id":"ssti-jinja2","scan":"per_insertion_point","severity":"high","payloads":["{{7*7}}"],"match":{"body_contains":"49"}}]` +
		"\n```\n"

	plan, err := ParseSwarmExtensions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if len(plan.QuickChecks) != 1 {
		t.Fatalf("expected 1 quick check, got %d", len(plan.QuickChecks))
	}
	if plan.QuickChecks[0].ID != "ssti-jinja2" {
		t.Errorf("expected ID 'ssti-jinja2', got %q", plan.QuickChecks[0].ID)
	}
}

func TestParseSwarmExtensionsNoExtensionsNeeded(t *testing.T) {
	input := "No custom extensions needed. The built-in modules cover all attack vectors."

	plan, err := ParseSwarmExtensions(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan != nil {
		t.Error("expected nil plan when no extensions needed")
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

// --- Tests for code-fenced, newline-separated values in parseCommaSeparated ---

func TestParseCommaSeparatedNewlineSeparated(t *testing.T) {
	// Agent outputs MODULE_IDS as newline-separated values
	input := "sqli-error-based\nsqli-union-based\nxss-reflected"
	got := parseCommaSeparated(input)
	if len(got) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(got), got)
	}
	if got[0] != "sqli-error-based" {
		t.Errorf("item[0]: expected 'sqli-error-based', got %q", got[0])
	}
}

func TestParseCommaSeparatedCodeFenced(t *testing.T) {
	// Agent wraps values in code fences
	input := "```\nidor\n```\nsqli-error-based\nsqli-union-based\nnosqli-boolean\n```"
	got := parseCommaSeparated(input)
	if len(got) != 4 {
		t.Fatalf("expected 4 items, got %d: %v", len(got), got)
	}
	if got[0] != "idor" {
		t.Errorf("item[0]: expected 'idor', got %q", got[0])
	}
}

func TestParseCommaSeparatedCodeFencedWithLang(t *testing.T) {
	// Code fence with language tag
	input := "```text\nsqli\nxss\n```"
	got := parseCommaSeparated(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 items, got %d: %v", len(got), got)
	}
}

func TestStripCodeFenceMarkers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no fences",
			input:    "sqli, xss",
			expected: "sqli, xss",
		},
		{
			name:     "simple fence",
			input:    "```\nyes\n```",
			expected: "yes",
		},
		{
			name:     "fence with language",
			input:    "```json\nyes\n```",
			expected: "yes",
		},
		{
			name:     "partial fences mixed with content",
			input:    "```\nidor\n```\nsqli-error-based\nxss-reflected\n```",
			expected: "idor\nsqli-error-based\nxss-reflected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCodeFenceMarkers(tt.input)
			if got != tt.expected {
				t.Errorf("stripCodeFenceMarkers(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// --- Tests for swarm plan with code-fenced MODULE_IDS/MODULE_TAGS ---

func TestParseSwarmPlanMarkdownCodeFencedModuleIDs(t *testing.T) {
	// Real-world pattern: agent wraps MODULE_IDS in code fences with newline-separated values
	input := `## MODULE_TAGS
sqli, xss, nosqli

## MODULE_IDS

` + "```" + `
idor
` + "```" + `
sqli-error-based
sqli-union-based
nosqli-boolean
nosqli-time-injection-based
xss-reflected
` + "```" + `

## FOCUS_AREAS
- SQL injection in login endpoint
- NoSQL injection in track order

## NOTES
Target is OWASP Juice Shop
`
	plan, err := ParseSwarmPlan(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.ModuleTags) != 3 {
		t.Errorf("expected 3 tags, got %d: %v", len(plan.ModuleTags), plan.ModuleTags)
	}
	if len(plan.ModuleIDs) < 5 {
		t.Errorf("expected at least 5 module IDs, got %d: %v", len(plan.ModuleIDs), plan.ModuleIDs)
	}
	// Ensure no code fence markers leaked into values
	for _, id := range plan.ModuleIDs {
		if strings.Contains(id, "```") {
			t.Errorf("module ID contains code fence marker: %q", id)
		}
		if strings.Contains(id, "\n") {
			t.Errorf("module ID contains newline: %q", id)
		}
	}
}

// --- Tests for ParseSourceAnalysisResult with multi-block output ---

func TestParseSourceAnalysisResultMultiBlockJSON(t *testing.T) {
	// SAST review output with multiple JSON blocks (Task 1, Task 2, Task 3)
	input := `## Task 1: Session Configuration

` + "```json" + `
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"http://localhost:3000/rest/user/login","method":"POST","content_type":"application/json","body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}}]}}
` + "```" + `

## Task 2: HTTP Routes

` + "```json" + `
{"http_records":[{"method":"POST","url":"http://localhost:3000/rest/user/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","notes":"Login endpoint"},{"method":"GET","url":"http://localhost:3000/rest/products/search?q=apple","headers":{},"body":"","notes":"Product search"}]}
` + "```" + `

## Task 3: SAST Extensions

` + "```json" + `
{"http_records":[{"method":"GET","url":"http://localhost:3000/rest/track-order/1234","headers":{},"body":"","notes":"Track order NoSQL injection"}]}
` + "```" + `

#### agent-sqli-login.js
Reason: SQL injection in login

` + "```javascript" + `
module.exports = {
  id: "agent-sqli-login",
  name: "SQLi Login",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return []; }
};
` + "```" + `
`
	result, err := ParseSourceAnalysisResult(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should merge http_records from all blocks (0 + 2 + 1 = 3)
	if len(result.HTTPRecords) != 3 {
		t.Errorf("expected 3 http_records (merged from 3 blocks), got %d", len(result.HTTPRecords))
	}

	// Should extract session config from Task 1
	if result.SessionConfig == nil {
		t.Error("expected session config to be extracted")
	}

	// Should extract extension from fenced JS code block
	if len(result.Extensions) != 1 {
		t.Errorf("expected 1 extension, got %d", len(result.Extensions))
	}
}

func TestParseSourceAnalysisResultExtensionsOnlyFallback(t *testing.T) {
	// When all JSON blocks are garbled, should still extract JS extensions
	input := `## Task 1
` + "```json" + `
{"http":_records[garbled json here}
` + "```" + `

#### agent-check.js
Reason: Custom check

` + "```javascript" + `
module.exports = {
  id: "agent-check",
  name: "Custom Check",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) { return []; }
};
` + "```" + `
`
	result, err := ParseSourceAnalysisResult(input)
	if err != nil {
		t.Fatalf("should not error when extensions can be extracted: %v", err)
	}
	if len(result.Extensions) != 1 {
		t.Errorf("expected 1 extension from fallback, got %d", len(result.Extensions))
	}
	if result.Extensions[0].Filename != "agent-check.js" {
		t.Errorf("expected filename 'agent-check.js', got %q", result.Extensions[0].Filename)
	}
}

func TestParseSourceAnalysisResultSingleBlock(t *testing.T) {
	// Standard single-block output still works
	input := `
` + "```json" + `
{"http_records":[{"method":"GET","url":"http://localhost:3000/api/Products","headers":{},"body":"","notes":"List products"}],"session_config":{"sessions":[{"name":"admin","role":"primary"}]}}
` + "```" + `
`
	result, err := ParseSourceAnalysisResult(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.HTTPRecords) != 1 {
		t.Errorf("expected 1 record, got %d", len(result.HTTPRecords))
	}
}

func TestExtractAllJSONFromFencedBlocks(t *testing.T) {
	input := `Some text

` + "```json" + `
{"key": "value1"}
` + "```" + `

More text

` + "```json" + `
{"key": "value2"}
` + "```" + `

` + "```javascript" + `
// This should be ignored
var x = 1;
` + "```" + `

` + "```json" + `
INVALID JSON
` + "```" + `
`
	blocks := extractAllJSONFromFencedBlocks(input)
	if len(blocks) != 2 {
		t.Fatalf("expected 2 valid JSON blocks, got %d", len(blocks))
	}
}

func TestMergeMultiBlockSourceAnalysis(t *testing.T) {
	// Test merging multiple valid JSON blocks
	input := `
` + "```json" + `
{"http_records":[{"method":"GET","url":"http://localhost/a"}],"session_config":{"sessions":[{"name":"admin","role":"primary"}]}}
` + "```" + `

` + "```json" + `
{"http_records":[{"method":"POST","url":"http://localhost/b"}]}
` + "```" + `
`
	result := mergeMultiBlockSourceAnalysis(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.HTTPRecords) != 2 {
		t.Errorf("expected 2 merged records, got %d", len(result.HTTPRecords))
	}
	if result.SessionConfig == nil {
		t.Error("expected session config from first block")
	}
}

func TestMergeMultiBlockSourceAnalysisNoValidBlocks(t *testing.T) {
	input := `No JSON here, just text`
	result := mergeMultiBlockSourceAnalysis(input)
	if result != nil {
		t.Error("expected nil result when no valid blocks")
	}
}
