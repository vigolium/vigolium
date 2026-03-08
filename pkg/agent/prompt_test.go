package agent

import (
	"strings"
	"testing"
)

func TestParseFrontmatter(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantFM    string
		wantBody  string
		wantErr   bool
	}{
		{
			name: "valid frontmatter",
			content: `---
id: test
name: Test Template
---
This is the body.`,
			wantFM:   "id: test\nname: Test Template",
			wantBody: "This is the body.",
			wantErr:  false,
		},
		{
			name:     "no frontmatter",
			content:  "Just a body with no frontmatter.",
			wantFM:   "",
			wantBody: "Just a body with no frontmatter.",
			wantErr:  false,
		},
		{
			name:    "unclosed frontmatter",
			content: "---\nid: test\nno closing delimiter",
			wantErr: true,
		},
		{
			name: "empty frontmatter",
			content: `---
---
Body content.`,
			wantFM:   "",
			wantBody: "Body content.",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, body, err := parseFrontmatter(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFrontmatter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if strings.TrimSpace(fm) != tt.wantFM {
					t.Errorf("frontmatter = %q, want %q", fm, tt.wantFM)
				}
				if strings.TrimSpace(body) != tt.wantBody {
					t.Errorf("body = %q, want %q", body, tt.wantBody)
				}
			}
		})
	}
}

func TestParseTemplate(t *testing.T) {
	raw := `---
id: security-code-review
name: Security Code Review
output_schema: findings
variables:
  - SourceCode
  - Language
---
Analyze this code:
{{.SourceCode}}`

	tmpl, err := parseTemplate(raw)
	if err != nil {
		t.Fatalf("parseTemplate() error = %v", err)
	}

	if tmpl.ID != "security-code-review" {
		t.Errorf("ID = %q, want %q", tmpl.ID, "security-code-review")
	}
	if tmpl.Name != "Security Code Review" {
		t.Errorf("Name = %q, want %q", tmpl.Name, "Security Code Review")
	}
	if tmpl.OutputSchema != "findings" {
		t.Errorf("OutputSchema = %q, want %q", tmpl.OutputSchema, "findings")
	}
	if len(tmpl.Variables) != 2 {
		t.Errorf("Variables = %v, want 2 items", tmpl.Variables)
	}
	if !strings.Contains(tmpl.Body, "{{.SourceCode}}") {
		t.Errorf("Body should contain template directive, got %q", tmpl.Body)
	}
}

func TestLoadTemplate_Embedded(t *testing.T) {
	// Point HOME to a temp dir so user templates at ~/.vigolium/prompts/ are not found.
	t.Setenv("HOME", t.TempDir())

	// Clear template cache to avoid stale entries from other tests.
	tmplCacheMu.Lock()
	clear(tmplCache)
	tmplCacheMu.Unlock()

	tmpl, err := LoadTemplate("security-code-review", "")
	if err != nil {
		t.Fatalf("LoadTemplate() error = %v", err)
	}

	if tmpl.ID != "security-code-review" {
		t.Errorf("ID = %q, want %q", tmpl.ID, "security-code-review")
	}
	if tmpl.Source != "embedded" {
		t.Errorf("Source = %q, want %q", tmpl.Source, "embedded")
	}
	if tmpl.OutputSchema != "findings" {
		t.Errorf("OutputSchema = %q, want %q", tmpl.OutputSchema, "findings")
	}
}

func TestLoadTemplate_NotFound(t *testing.T) {
	_, err := LoadTemplate("nonexistent-template", "")
	if err == nil {
		t.Error("LoadTemplate() should return error for nonexistent template")
	}
}

func TestRenderTemplate(t *testing.T) {
	tmpl := &PromptTemplate{
		ID:   "test",
		Body: "Review {{.Language}} code:\n{{.SourceCode}}",
	}
	data := TemplateData{
		Language:   "Go",
		SourceCode: "func main() {}",
	}

	rendered, err := RenderTemplate(tmpl, data)
	if err != nil {
		t.Fatalf("RenderTemplate() error = %v", err)
	}

	if !strings.Contains(rendered, "Go") {
		t.Errorf("rendered should contain language, got %q", rendered)
	}
	if !strings.Contains(rendered, "func main() {}") {
		t.Errorf("rendered should contain source code, got %q", rendered)
	}
}

func TestRenderTemplate_MissingVars(t *testing.T) {
	tmpl := &PromptTemplate{
		ID:   "test",
		Body: "Language: {{.Language}}\nFramework: {{.Framework}}",
	}
	data := TemplateData{
		Language: "Python",
		// Framework is empty — should render as empty string
	}

	rendered, err := RenderTemplate(tmpl, data)
	if err != nil {
		t.Fatalf("RenderTemplate() error = %v", err)
	}

	if !strings.Contains(rendered, "Python") {
		t.Errorf("rendered should contain language, got %q", rendered)
	}
}

func TestListTemplates(t *testing.T) {
	templates, err := ListTemplates("")
	if err != nil {
		t.Fatalf("ListTemplates() error = %v", err)
	}

	if len(templates) == 0 {
		t.Fatal("expected at least one embedded template")
	}

	// Check that security-code-review is in the list
	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "security-code-review" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected security-code-review template in list")
	}
}
