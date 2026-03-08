package astgrep

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		scanner, err := NewScanner(nil)
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		if scanner == nil {
			t.Error("expected non-nil scanner")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &Config{
			CacheDir: t.TempDir(),
		}
		scanner, err := NewScanner(config)
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		if scanner == nil {
			t.Error("expected non-nil scanner")
		}
	})
}

func TestScanner_Version(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	// Before any scan, version should be empty
	if v := scanner.Version(); v != "" {
		t.Errorf("expected empty version before scan, got %q", v)
	}
}

func TestScanner_BinaryPath(t *testing.T) {
	config := &Config{
		CacheDir: t.TempDir(),
	}
	scanner, err := NewScanner(config)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	// Before any scan, binary path should be empty
	if p := scanner.BinaryPath(); p != "" {
		t.Errorf("expected empty binary path before scan, got %q", p)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if !config.AutoUpdate {
		t.Error("expected AutoUpdate to be true")
	}
	if config.HTTPTimeout != 60*time.Second {
		t.Errorf("expected 60s HTTP timeout, got %v", config.HTTPTimeout)
	}
	if config.CacheDir != "" {
		t.Errorf("expected empty CacheDir (default), got %q", config.CacheDir)
	}
	if config.Version != "" {
		t.Errorf("expected empty Version (latest), got %q", config.Version)
	}
}

func TestScanResult_HasMatches(t *testing.T) {
	t.Run("empty matches", func(t *testing.T) {
		result := &ScanResult{Matches: []Match{}}
		if result.HasMatches() {
			t.Error("expected HasMatches to return false for empty matches")
		}
	})

	t.Run("with matches", func(t *testing.T) {
		result := &ScanResult{
			Matches: []Match{{ID: "test", Text: "code"}},
		}
		if !result.HasMatches() {
			t.Error("expected HasMatches to return true")
		}
	})
}

func TestParseAstGrepOutput(t *testing.T) {
	t.Run("empty output", func(t *testing.T) {
		matches, err := parseAstGrepOutput([]byte{})
		if err != nil {
			t.Fatalf("parseAstGrepOutput: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})

	t.Run("json array", func(t *testing.T) {
		output := `[
			{
				"id": "gin-route-handler",
				"text": "r.GET(\"/api/users\", listUsers)",
				"range": {"start": {"line": 10, "column": 1, "offset": 100}, "end": {"line": 10, "column": 35, "offset": 134}},
				"file": "main.go",
				"language": "go",
				"message": "Route: GET /api/users",
				"severity": "info",
				"metaVariables": {
					"METHOD": {"text": "GET", "range": {"start": {"line": 10, "column": 3, "offset": 102}, "end": {"line": 10, "column": 6, "offset": 105}}},
					"PATH": {"text": "\"/api/users\"", "range": {"start": {"line": 10, "column": 7, "offset": 106}, "end": {"line": 10, "column": 19, "offset": 118}}}
				}
			},
			{
				"id": "gin-route-handler",
				"text": "r.POST(\"/api/users\", createUser)",
				"range": {"start": {"line": 11, "column": 1, "offset": 135}, "end": {"line": 11, "column": 37, "offset": 171}},
				"file": "main.go",
				"language": "go",
				"message": "Route: POST /api/users",
				"severity": "info",
				"metaVariables": {
					"METHOD": {"text": "POST", "range": {"start": {"line": 11, "column": 3, "offset": 137}, "end": {"line": 11, "column": 7, "offset": 141}}},
					"PATH": {"text": "\"/api/users\"", "range": {"start": {"line": 11, "column": 8, "offset": 142}, "end": {"line": 11, "column": 20, "offset": 154}}}
				}
			}
		]`
		matches, err := parseAstGrepOutput([]byte(output))
		if err != nil {
			t.Fatalf("parseAstGrepOutput: %v", err)
		}
		if len(matches) != 2 {
			t.Errorf("expected 2 matches, got %d", len(matches))
		}
		if matches[0].ID != "gin-route-handler" {
			t.Errorf("expected id 'gin-route-handler', got %q", matches[0].ID)
		}
		if matches[0].File != "main.go" {
			t.Errorf("expected file 'main.go', got %q", matches[0].File)
		}
	})

	t.Run("empty json array", func(t *testing.T) {
		matches, err := parseAstGrepOutput([]byte("[]"))
		if err != nil {
			t.Fatalf("parseAstGrepOutput: %v", err)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})
}

func TestMatchesToRoutes(t *testing.T) {
	matches := []Match{
		{
			ID:      "gin-route-handler",
			Text:    `r.GET("/api/users", listUsers)`,
			Range:   MatchRange{Start: Position{Line: 10}},
			File:    "main.go",
			Message: "Route: GET /api/users",
			MetaVariables: map[string]MetaVariable{
				"METHOD": {Text: "GET"},
				"PATH":   {Text: `"/api/users"`},
			},
		},
		{
			ID:      "gin-route-handler",
			Text:    `r.POST("/api/users", createUser)`,
			Range:   MatchRange{Start: Position{Line: 15}},
			File:    "main.go",
			Message: "Route: POST /api/users",
			MetaVariables: map[string]MetaVariable{
				"METHOD": {Text: "POST"},
				"PATH":   {Text: `"/api/users"`},
			},
		},
		{
			ID:      "gin-param-binding",
			Text:    `c.Param("id")`,
			Range:   MatchRange{Start: Position{Line: 20}},
			File:    "handlers.go",
			Message: "Route: PARAM id",
			MetaVariables: map[string]MetaVariable{
				"PARAMS": {Text: `"id"`},
			},
		},
	}

	routes := MatchesToRoutes(matches)
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}

	// Check first route
	if routes[0].Method != "GET" {
		t.Errorf("expected method GET, got %q", routes[0].Method)
	}
	if routes[0].Path != "/api/users" {
		t.Errorf("expected path /api/users, got %q", routes[0].Path)
	}
	if routes[0].File != "main.go" {
		t.Errorf("expected file main.go, got %q", routes[0].File)
	}
	if routes[0].Line != 11 { // 0-based to 1-based
		t.Errorf("expected line 11, got %d", routes[0].Line)
	}

	// Check second route
	if routes[1].Method != "POST" {
		t.Errorf("expected method POST, got %q", routes[1].Method)
	}
}

func TestCleanPathValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"/api/users"`, "/api/users"},
		{`'/api/users'`, "/api/users"},
		{"/api/users", "/api/users"},
		{`  "/api/users"  `, "/api/users"},
		{"", ""},
	}

	for _, tt := range tests {
		result := cleanPathValue(tt.input)
		if result != tt.expected {
			t.Errorf("cleanPathValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseParams(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"id", []string{"id"}},
		{"id, name", []string{"id", "name"}},
		{"id: int, name: str", []string{"id", "name"}},
		{"id: int = 0, name: str = ''", []string{"id", "name"}},
		{"", nil},
		{"  ", nil},
	}

	for _, tt := range tests {
		result := parseParams(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("parseParams(%q): expected %d params, got %d: %v", tt.input, len(tt.expected), len(result), result)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("parseParams(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}

func TestIsHTTPMethod(t *testing.T) {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ANY", "HANDLE", "ALL",
		"LIST", "CREATE", "RETRIEVE", "UPDATE", "DESTROY", "CONNECT", "TRACE"}
	for _, m := range validMethods {
		if !isHTTPMethod(m) {
			t.Errorf("expected %q to be a valid HTTP method", m)
		}
	}

	invalidMethods := []string{"get", "UNKNOWN", ""}
	for _, m := range invalidMethods {
		if isHTTPMethod(m) {
			t.Errorf("expected %q to NOT be a valid HTTP method", m)
		}
	}
}

func TestDetectFramework(t *testing.T) {
	t.Run("gin detection", func(t *testing.T) {
		dir := t.TempDir()
		gomod := `module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
`
		if err := writeTestFile(dir, "go.mod", gomod); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "gin" {
			t.Errorf("expected gin, got %q", fw)
		}
	})

	t.Run("nextjs detection", func(t *testing.T) {
		dir := t.TempDir()
		pkg := `{
  "name": "my-app",
  "dependencies": {
    "next": "^14.0.0",
    "react": "^18.0.0"
  }
}`
		if err := writeTestFile(dir, "package.json", pkg); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "nextjs" {
			t.Errorf("expected nextjs, got %q", fw)
		}
	})

	t.Run("fastapi detection", func(t *testing.T) {
		dir := t.TempDir()
		req := "fastapi==0.100.0\nuvicorn==0.23.0\n"
		if err := writeTestFile(dir, "requirements.txt", req); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "fastapi" {
			t.Errorf("expected fastapi, got %q", fw)
		}
	})

	t.Run("express detection", func(t *testing.T) {
		dir := t.TempDir()
		pkg := `{
  "name": "my-api",
  "dependencies": {
    "express": "^4.18.0"
  }
}`
		if err := writeTestFile(dir, "package.json", pkg); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "express" {
			t.Errorf("expected express, got %q", fw)
		}
	})

	t.Run("django detection via manage.py", func(t *testing.T) {
		dir := t.TempDir()
		manage := `#!/usr/bin/env python
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myapp.settings')
from django.core.management import execute_from_command_line
`
		if err := writeTestFile(dir, "manage.py", manage); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "django" {
			t.Errorf("expected django, got %q", fw)
		}
	})

	t.Run("django detection via requirements.txt", func(t *testing.T) {
		dir := t.TempDir()
		req := "django==4.2.0\ngunicorn==21.2.0\n"
		if err := writeTestFile(dir, "requirements.txt", req); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "django" {
			t.Errorf("expected django, got %q", fw)
		}
	})

	t.Run("flask detection", func(t *testing.T) {
		dir := t.TempDir()
		req := "flask==3.0.0\ngunicorn==21.2.0\n"
		if err := writeTestFile(dir, "requirements.txt", req); err != nil {
			t.Fatal(err)
		}

		fw := DetectFramework(dir)
		if fw != "flask" {
			t.Errorf("expected flask, got %q", fw)
		}
	})

	t.Run("no detection", func(t *testing.T) {
		dir := t.TempDir()
		fw := DetectFramework(dir)
		if fw != "" {
			t.Errorf("expected empty, got %q", fw)
		}
	})
}

func TestAvailableFrameworks(t *testing.T) {
	frameworks := AvailableFrameworks()
	if len(frameworks) != 7 {
		t.Errorf("expected 7 frameworks, got %d", len(frameworks))
	}
}

func TestExtractRules(t *testing.T) {
	t.Run("gin rules", func(t *testing.T) {
		dir, err := ExtractRules("gin", "")
		if err != nil {
			t.Fatalf("ExtractRules: %v", err)
		}
		// Verify rules were extracted
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) == 0 {
			t.Error("expected at least one rule file extracted")
		}
		// Clean up
		_ = os.RemoveAll(dir)
	})

	t.Run("express rules", func(t *testing.T) {
		dir, err := ExtractRules("express", "")
		if err != nil {
			t.Fatalf("ExtractRules: %v", err)
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) == 0 {
			t.Error("expected at least one rule file extracted")
		}
		_ = os.RemoveAll(dir)
	})

	t.Run("django rules", func(t *testing.T) {
		dir, err := ExtractRules("django", "")
		if err != nil {
			t.Fatalf("ExtractRules: %v", err)
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) == 0 {
			t.Error("expected at least one rule file extracted")
		}
		_ = os.RemoveAll(dir)
	})

	t.Run("flask rules", func(t *testing.T) {
		dir, err := ExtractRules("flask", "")
		if err != nil {
			t.Fatalf("ExtractRules: %v", err)
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) == 0 {
			t.Error("expected at least one rule file extracted")
		}
		_ = os.RemoveAll(dir)
	})

	t.Run("gohttp rules", func(t *testing.T) {
		dir, err := ExtractRules("gohttp", "")
		if err != nil {
			t.Fatalf("ExtractRules: %v", err)
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) == 0 {
			t.Error("expected at least one rule file extracted")
		}
		_ = os.RemoveAll(dir)
	})

	t.Run("unsupported framework", func(t *testing.T) {
		_, err := ExtractRules("rails", "")
		if err == nil {
			t.Error("expected error for unsupported framework")
		}
	})
}

func TestExtractAllRules(t *testing.T) {
	dir, err := ExtractAllRules("")
	if err != nil {
		t.Fatalf("ExtractAllRules: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}

	// We have 7 frameworks: gin(3) + nextjs(3) + fastapi(3) + express(6) + django(3) + flask(3) + gohttp(3) = 24
	if len(entries) < 24 {
		t.Errorf("expected at least 24 rule files from all frameworks, got %d", len(entries))
	}

	// Check that files are prefixed with framework names
	prefixes := map[string]bool{
		"gin-":     false,
		"nextjs-":  false,
		"fastapi-": false,
		"express-": false,
		"django-":  false,
		"flask-":   false,
		"gohttp-":  false,
	}
	for _, e := range entries {
		name := e.Name()
		for prefix := range prefixes {
			if len(name) > len(prefix) && name[:len(prefix)] == prefix {
				prefixes[prefix] = true
			}
		}
	}
	for prefix, found := range prefixes {
		if !found {
			t.Errorf("expected %sprefixed rules", prefix)
		}
	}
}

func TestExtractMatchingRules(t *testing.T) {
	t.Run("filter by framework name", func(t *testing.T) {
		dir, err := ExtractMatchingRules("gin/", "")
		if err != nil {
			t.Fatalf("ExtractMatchingRules: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}

		if len(entries) == 0 {
			t.Error("expected at least one gin rule file")
		}

		// All files should be gin rules
		for _, e := range entries {
			if len(e.Name()) < 4 || e.Name()[:4] != "gin-" {
				t.Errorf("expected gin-prefixed file, got %q", e.Name())
			}
		}
	})

	t.Run("filter by partial filename", func(t *testing.T) {
		dir, err := ExtractMatchingRules("route", "")
		if err != nil {
			t.Fatalf("ExtractMatchingRules: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}

		if len(entries) == 0 {
			t.Error("expected at least one rule file matching 'route'")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		dir, err := ExtractMatchingRules("GIN", "")
		if err != nil {
			t.Fatalf("ExtractMatchingRules: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}

		if len(entries) == 0 {
			t.Error("expected at least one gin rule file with case-insensitive match")
		}
	})

	t.Run("empty pattern falls back to all", func(t *testing.T) {
		dir, err := ExtractMatchingRules("", "")
		if err != nil {
			t.Fatalf("ExtractMatchingRules: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()

		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}

		if len(entries) < 24 {
			t.Errorf("expected at least 24 rule files for empty pattern, got %d", len(entries))
		}
	})

	t.Run("no matches", func(t *testing.T) {
		_, err := ExtractMatchingRules("nonexistent-framework-xyz", "")
		if err == nil {
			t.Error("expected error for non-matching pattern")
		}
	})
}

func writeTestFile(dir, name, content string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
}
