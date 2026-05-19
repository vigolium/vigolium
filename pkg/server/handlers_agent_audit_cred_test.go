package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageInlineCredJSON_HappyPath(t *testing.T) {
	dir := t.TempDir()
	raw := `{"auth_mode":"codex","tokens":{"id_token":"x","access_token":"y","refresh_token":"z","account_id":"a"}}`

	path, cleanup, err := stageInlineCredJSON(dir, raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(cleanup)

	if !strings.HasPrefix(path, filepath.Join(dir, byokCredDirName)) {
		t.Errorf("staged path not under byok-creds: %s", path)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged: %v", err)
	}
	if string(got) != raw {
		t.Errorf("staged content mismatch: %s", got)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat staged: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("staged mode = %o, want 0600", mode)
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup left the file behind: %v", err)
	}
}

func TestStageInlineCredJSON_EmptyInputIsNoop(t *testing.T) {
	dir := t.TempDir()
	path, cleanup, err := stageInlineCredJSON(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path on empty input, got %q", path)
	}
	cleanup() // must not panic on the no-op closure
}

func TestStageInlineCredJSON_RejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	_, _, err := stageInlineCredJSON(dir, "this is not json")
	if err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("wrong error message: %v", err)
	}
}

func TestStageInlineCredJSON_RejectsMissingTokens(t *testing.T) {
	dir := t.TempDir()
	_, _, err := stageInlineCredJSON(dir, `{"auth_mode":"codex"}`)
	if err == nil {
		t.Fatalf("expected error for missing tokens object")
	}
	if !strings.Contains(err.Error(), "tokens") {
		t.Errorf("error should mention tokens: %v", err)
	}
}
