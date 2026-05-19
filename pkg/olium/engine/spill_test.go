package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/provider"
)

func TestSpillToolResultWritesFullPayload(t *testing.T) {
	dir := t.TempDir()
	tc := provider.ToolCall{ID: "call-abc", Name: "grep"}
	full := strings.Repeat("X", 100_000)

	got, ok := spillToolResult(dir, tc, full, 16*1024)
	if !ok {
		t.Fatal("spillToolResult should succeed on a writable temp dir")
	}

	// The shrunk content must point at a real file.
	if !strings.Contains(got, "tool-results") {
		t.Errorf("shrunk content should mention spill path, got:\n%s", got)
	}

	// Verify the file actually exists and contains the full payload.
	matches, err := filepath.Glob(filepath.Join(dir, "tool-results", "grep-call-abc.txt"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one spilled file, glob err=%v matches=%v", err, matches)
	}
	body, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read spilled file: %v", err)
	}
	if string(body) != full {
		t.Errorf("spilled file should contain full payload (got %d bytes, want %d)", len(body), len(full))
	}
}

func TestSpillToolResultBudgetTooTight(t *testing.T) {
	dir := t.TempDir()
	tc := provider.ToolCall{ID: "x", Name: "y"}
	got, ok := spillToolResult(dir, tc, strings.Repeat("z", 1000), 200)
	if !ok {
		t.Fatal("should still succeed with tight budget")
	}
	if !strings.Contains(got, "spilled to disk") {
		t.Errorf("tight-budget path should fall back to pointer-only, got:\n%s", got)
	}
}

func TestSpillToolResultFailsOnUnwritablePath(t *testing.T) {
	tc := provider.ToolCall{ID: "x", Name: "y"}
	// /proc on macOS doesn't exist; on Linux it does but is read-only.
	// Using a non-existent file as a "directory" guarantees MkdirAll fails.
	target := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, ok := spillToolResult(target, tc, "data", 16*1024)
	if ok {
		t.Error("spillToolResult should fail when dir path is a regular file")
	}
}

func TestSanitizeSpillSegment(t *testing.T) {
	cases := map[string]string{
		"abc-123":         "abc-123",
		"":                "x",
		"path/with/slash": "path-with-slash",
		"weird::id":       "weird--id",
	}
	for in, want := range cases {
		if got := sanitizeSpillSegment(in); got != want {
			t.Errorf("sanitizeSpillSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShrinkToolResultFallsBackToTruncate(t *testing.T) {
	// No SpillDir → engine should head+tail truncate as before.
	e := &Engine{maxToolResultLen: 1000}
	tc := provider.ToolCall{ID: "x", Name: "y"}
	full := strings.Repeat("a", 5000)
	got := e.shrinkToolResult(tc, full)
	// Truncation reserves room for the elision marker but the real digits
	// in the marker can grow by a few bytes once formatted; allow a small
	// slack rather than pinning to the exact cap.
	if len(got) > 1100 {
		t.Errorf("should be truncated near maxToolResultLen=1000, got %d bytes", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Error("expected truncation marker in fallback path")
	}
}

func TestShrinkToolResultUsesSpillWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{cfg: Config{SpillDir: dir}, maxToolResultLen: 1000}
	tc := provider.ToolCall{ID: "tid", Name: "bash"}
	full := strings.Repeat("b", 5000)
	got := e.shrinkToolResult(tc, full)
	if !strings.Contains(got, "tool-results") {
		t.Errorf("expected spill pointer, got:\n%s", got)
	}
	// And the spill file should exist.
	matches, _ := filepath.Glob(filepath.Join(dir, "tool-results", "bash-tid.txt"))
	if len(matches) != 1 {
		t.Errorf("expected exactly one spill file, got %v", matches)
	}
}

func TestShrinkToolResultPassesThroughSmallContent(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{cfg: Config{SpillDir: dir}, maxToolResultLen: 1000}
	tc := provider.ToolCall{ID: "tid", Name: "ls"}
	got := e.shrinkToolResult(tc, "hello world")
	if got != "hello world" {
		t.Errorf("small content should pass through, got %q", got)
	}
	// And no spill file should be created.
	matches, _ := filepath.Glob(filepath.Join(dir, "tool-results", "*"))
	if len(matches) != 0 {
		t.Errorf("expected no spill files for small content, got %v", matches)
	}
}
