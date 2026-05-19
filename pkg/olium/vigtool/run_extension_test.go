package vigtool

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveExtensionPathFromExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ext.js")
	if err := os.WriteFile(path, []byte("module.exports = {};"), 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, cleanup, err := resolveExtensionPath(path, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanup != nil {
		t.Error("cleanup should be nil when caller supplied an existing path")
	}
	if !filepath.IsAbs(resolved) {
		t.Errorf("resolved path should be absolute, got %q", resolved)
	}
	if _, err := os.Stat(resolved); err != nil {
		t.Errorf("resolved file should exist: %v", err)
	}
}

func TestResolveExtensionPathMissingFile(t *testing.T) {
	_, _, err := resolveExtensionPath("/definitely/does/not/exist.js", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestResolveExtensionPathFromInlineSource(t *testing.T) {
	source := `module.exports = { id: "t", type: "passive", scanPerRequest: function(){return null;} };`
	resolved, cleanup, err := resolveExtensionPath("", source)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup should be non-nil for inline source")
	}
	defer cleanup()

	body, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatalf("temp file should be readable: %v", err)
	}
	if string(body) != source {
		t.Errorf("temp file content mismatch")
	}
	if !strings.HasSuffix(resolved, ".js") {
		t.Errorf("temp file should keep .js suffix, got %q", resolved)
	}

	// Cleanup should actually remove the file.
	cleanup()
	if _, err := os.Stat(resolved); !os.IsNotExist(err) {
		t.Errorf("cleanup should remove temp file, stat err = %v", err)
	}
}

// TestRunExtensionRejectsConflictingArgs covers the validation paths that
// run before any work happens — these are pure input checks and worth
// pinning so we don't regress them.
func TestRunExtensionRejectsConflictingArgs(t *testing.T) {
	tool := NewRunExtensionTool(&ScanContext{})
	ctx := context.Background()

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{
			name: "no targets",
			args: map[string]any{"script_source": "x"},
			want: "targets",
		},
		{
			name: "neither path nor source",
			args: map[string]any{"targets": []any{"https://x"}},
			want: "script_path",
		},
		{
			name: "both path and source",
			args: map[string]any{
				"targets":       []any{"https://x"},
				"script_path":   "/x.js",
				"script_source": "y",
			},
			want: "mutually exclusive",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := tool.Execute(ctx, c.args, nil)
			if err != nil {
				t.Fatalf("Execute should not return go-level error, got %v", err)
			}
			if !res.IsError {
				t.Error("expected res.IsError = true")
			}
			if !strings.Contains(strings.ToLower(res.Content), c.want) {
				t.Errorf("expected message to mention %q, got: %s", c.want, res.Content)
			}
		})
	}
}

func TestRunScanRejectsEmptyTargets(t *testing.T) {
	tool := NewRunScanTool(&ScanContext{})
	res, err := tool.Execute(context.Background(), map[string]any{}, nil)
	if err != nil {
		t.Fatalf("Execute should not return go-level error: %v", err)
	}
	if !res.IsError {
		t.Error("expected res.IsError = true")
	}
	if !strings.Contains(res.Content, "targets") {
		t.Errorf("expected message to mention targets, got: %s", res.Content)
	}
}
