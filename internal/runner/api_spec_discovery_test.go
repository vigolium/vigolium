package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPostmanCollection(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "valid postman v2.1 collection",
			data: `{
				"info": {
					"name": "Test API",
					"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
				},
				"item": [
					{"name": "Get Users", "request": {"method": "GET", "url": {"raw": "https://api.example.com/users"}}}
				]
			}`,
			want: true,
		},
		{
			name: "valid wrapped postman collection",
			data: `{
				"collection": {
					"info": {
						"name": "Test API",
						"schema": "https://schema.getpostman.com/json/collection/v2.0.0/collection.json"
					},
					"item": [
						{"name": "Get Users"}
					]
				}
			}`,
			want: true,
		},
		{
			name: "openapi spec is not postman",
			data: `{"openapi": "3.0.0", "info": {"title": "Test"}, "paths": {}}`,
			want: false,
		},
		{
			name: "random json",
			data: `{"foo": "bar", "baz": 123}`,
			want: false,
		},
		{
			name: "invalid json",
			data: `not json at all`,
			want: false,
		},
		{
			name: "empty json object",
			data: `{}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPostmanCollection([]byte(tt.data))
			if got != tt.want {
				t.Errorf("isPostmanCollection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarkdownHasCurlCommands(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "curl in fenced code block",
			content: "# API Docs\n\n```bash\ncurl -X GET https://api.example.com/users\n```\n",
			want: true,
		},
		{
			name: "curl with multiline in code block",
			content: "# API\n\n```\ncurl -X POST https://api.example.com/users \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"name\": \"test\"}'\n```\n",
			want: true,
		},
		{
			name: "curl outside code block is ignored",
			content: "# API Docs\n\nRun `curl https://api.example.com/users` to test.\n",
			want: false,
		},
		{
			name: "no curl at all",
			content: "# README\n\nThis is a project.\n\n```python\nprint('hello')\n```\n",
			want: false,
		},
		{
			name: "empty markdown",
			content: "",
			want: false,
		},
		{
			name: "multiple code blocks with curl in second",
			content: "```js\nconsole.log('hi')\n```\n\n```bash\ncurl -X GET https://api.example.com/health\n```\n",
			want: true,
		},
		{
			name: "code block without curl",
			content: "```bash\necho hello\nwget https://example.com\n```\n",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := markdownHasCurlCommands(tt.content)
			if got != tt.want {
				t.Errorf("markdownHasCurlCommands() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoverAPISpecs(t *testing.T) {
	// Create a temporary directory structure with spec files
	tmpDir := t.TempDir()

	// Create subdirectories
	if err := os.MkdirAll(filepath.Join(tmpDir, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "api"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Write an OpenAPI 3.0 spec
	openapiJSON := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"paths": {
			"/users": {
				"get": {"summary": "List users", "responses": {"200": {"description": "OK"}}}
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "docs", "openapi.json"), []byte(openapiJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a Swagger 2.0 spec (YAML)
	swaggerYAML := `swagger: "2.0"
info:
  title: Test API
  version: "1.0"
basePath: /api/v1
paths:
  /items:
    get:
      summary: List items
      responses:
        200:
          description: OK
`
	if err := os.WriteFile(filepath.Join(tmpDir, "api", "swagger.yaml"), []byte(swaggerYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a Postman collection
	postmanJSON := `{
		"info": {
			"name": "Test API",
			"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
		},
		"item": [
			{
				"name": "Get Users",
				"request": {
					"method": "GET",
					"url": {"raw": "https://api.example.com/users"}
				}
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "docs", "api.postman_collection.json"), []byte(postmanJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a markdown file with curl commands in code blocks
	curlMD := "# API Documentation\n\n## Get Users\n\n```bash\ncurl -X GET https://api.example.com/users \\\n  -H 'Authorization: Bearer token123'\n```\n\n## Create User\n\n```bash\ncurl -X POST https://api.example.com/users \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"name\": \"test\"}'\n```\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "docs", "API.md"), []byte(curlMD), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a markdown file WITHOUT curl commands (should be ignored)
	plainMD := "# README\n\nThis project is great.\n\n```python\nprint('hello world')\n```\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte(plainMD), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a spec inside node_modules (should be skipped)
	if err := os.WriteFile(filepath.Join(tmpDir, "node_modules", "pkg", "openapi.json"), []byte(openapiJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a non-spec JSON file (should be ignored)
	if err := os.WriteFile(filepath.Join(tmpDir, "src", "config.json"), []byte(`{"port": 8080, "debug": true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a tiny file (should be ignored)
	if err := os.WriteFile(filepath.Join(tmpDir, "api", "tiny.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run discovery
	specs := discoverAPISpecs(tmpDir)

	// Verify results: 2 openapi + 1 postman + 1 curl-md = 4
	if len(specs) != 4 {
		t.Fatalf("expected 4 specs, got %d: %+v", len(specs), specs)
	}

	// Collect by type
	typeCount := map[string]int{}
	relPaths := map[string]string{}
	for _, s := range specs {
		typeCount[s.specType]++
		relPaths[s.relPath] = s.specType
	}

	if typeCount["openapi"] != 2 {
		t.Errorf("expected 2 openapi specs, got %d", typeCount["openapi"])
	}
	if typeCount["postman"] != 1 {
		t.Errorf("expected 1 postman spec, got %d", typeCount["postman"])
	}
	if typeCount["curl-md"] != 1 {
		t.Errorf("expected 1 curl-md spec, got %d", typeCount["curl-md"])
	}

	// Check that node_modules spec was skipped
	for _, s := range specs {
		if filepath.Base(filepath.Dir(s.path)) == "node_modules" {
			t.Errorf("node_modules spec should have been skipped: %s", s.path)
		}
	}

	// Check that config.json was not detected
	if _, ok := relPaths[filepath.Join("src", "config.json")]; ok {
		t.Error("config.json should not be detected as an API spec")
	}

	// Check that plain README.md was not detected
	if _, ok := relPaths["README.md"]; ok {
		t.Error("README.md without curl commands should not be detected")
	}

	// Check that API.md was detected as curl-md
	if typ, ok := relPaths[filepath.Join("docs", "API.md")]; !ok || typ != "curl-md" {
		t.Errorf("docs/API.md should be detected as curl-md, got %q (found=%v)", typ, ok)
	}
}

func TestDiscoverAPISpecs_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	specs := discoverAPISpecs(tmpDir)
	if len(specs) != 0 {
		t.Errorf("expected 0 specs in empty dir, got %d", len(specs))
	}
}

func TestDiscoverAPISpecs_NonexistentDir(t *testing.T) {
	specs := discoverAPISpecs("/tmp/nonexistent-vigolium-test-dir-12345")
	if len(specs) != 0 {
		t.Errorf("expected 0 specs for nonexistent dir, got %d", len(specs))
	}
}
