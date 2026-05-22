package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestEnsureSessionDir(t *testing.T) {
	t.Run("creates dir under explicit base", func(t *testing.T) {
		base := t.TempDir()
		dir, err := EnsureSessionDir(base, "run-123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dir != filepath.Join(base, "run-123") {
			t.Errorf("dir = %q, want %q", dir, filepath.Join(base, "run-123"))
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("expected created directory, stat err=%v", err)
		}
	})

	t.Run("idempotent on existing dir", func(t *testing.T) {
		base := t.TempDir()
		if _, err := EnsureSessionDir(base, "run-x"); err != nil {
			t.Fatal(err)
		}
		if _, err := EnsureSessionDir(base, "run-x"); err != nil {
			t.Errorf("second call should not error: %v", err)
		}
	})

	t.Run("empty base defaults under HOME/.vigolium", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		dir, err := EnsureSessionDir("", "run-home")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(home, ".vigolium", "agent-sessions", "run-home")
		if dir != want {
			t.Errorf("dir = %q, want %q", dir, want)
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("default session dir not created: %v", err)
		}
	})
}

func TestResolveModulesFromPlan(t *testing.T) {
	t.Run("empty tags and ids falls back to all", func(t *testing.T) {
		got := ResolveModulesFromPlan(nil, nil)
		if len(got) != 1 || got[0] != "all" {
			t.Errorf("expected [all], got %v", got)
		}
	})

	t.Run("explicit ids are deduplicated", func(t *testing.T) {
		got := ResolveModulesFromPlan(nil, []string{"mod-a", "mod-b", "mod-a"})
		sort.Strings(got)
		if len(got) != 2 || got[0] != "mod-a" || got[1] != "mod-b" {
			t.Errorf("expected deduped [mod-a mod-b], got %v", got)
		}
	})
}

func TestCheckpointRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// writeCheckpoint with empty dir is a no-op (returns nil).
	if err := writeCheckpoint("", &SwarmCheckpoint{}); err != nil {
		t.Errorf("empty dir should be a no-op, got %v", err)
	}

	cp := &SwarmCheckpoint{
		TargetURL:       "http://scan-xyz",
		RecordCount:     7,
		CompletedPhases: []string{"normalize", "plan"},
	}
	if err := WriteCheckpointToDir(dir, cp); err != nil {
		t.Fatalf("WriteCheckpointToDir error: %v", err)
	}
	// File should exist.
	if _, err := os.Stat(filepath.Join(dir, "checkpoint.json")); err != nil {
		t.Fatalf("checkpoint.json not written: %v", err)
	}

	loaded, err := loadCheckpoint(dir)
	if err != nil {
		t.Fatalf("loadCheckpoint error: %v", err)
	}
	if loaded.TargetURL != "http://scan-xyz" || loaded.RecordCount != 7 {
		t.Errorf("loaded checkpoint = %+v, want target/record preserved", loaded)
	}
	if loaded.LastPhase() != "plan" {
		t.Errorf("LastPhase = %q, want plan", loaded.LastPhase())
	}

	// loadCheckpoint on a dir with no checkpoint returns an error.
	if _, err := loadCheckpoint(t.TempDir()); err == nil {
		t.Error("loadCheckpoint on empty dir should error")
	}
}

func TestWriteExtensionsToSessionDir(t *testing.T) {
	dir := t.TempDir()
	exts := []GeneratedExtension{
		{Filename: "Check One.js", Code: "module.exports={}", Reason: "r1"},
		{Filename: "../evil.js", Code: "x", Reason: "r2"},
	}
	extDir, err := WriteExtensionsToSessionDir(exts, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if extDir != filepath.Join(dir, "extensions") {
		t.Errorf("extDir = %q, want .../extensions", extDir)
	}
	entries, err := os.ReadDir(extDir)
	if err != nil {
		t.Fatalf("read extensions dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	// "Check One.js" → "check-one.js", "../evil.js" → "evil.js"
	if len(names) != 2 || names[0] != "check-one.js" || names[1] != "evil.js" {
		t.Errorf("written files = %v, want [check-one.js evil.js]", names)
	}
}

func TestWriteExtensionsToTempDir(t *testing.T) {
	exts := []GeneratedExtension{{Filename: "scan.js", Code: "code"}}
	dir, err := WriteExtensionsToTempDir(exts, "vig-test-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(dir)
	data, err := os.ReadFile(filepath.Join(dir, "scan.js"))
	if err != nil {
		t.Fatalf("expected scan.js: %v", err)
	}
	if string(data) != "code" {
		t.Errorf("content = %q, want code", string(data))
	}
}

func TestRepairPromptBuilders(t *testing.T) {
	hp := buildHTTPRecordRepairPrompt("garbled{json")
	if !strings.Contains(hp, "garbled{json") || !strings.Contains(hp, "jsonl") {
		t.Errorf("HTTP record repair prompt missing input or jsonl hint")
	}

	sp := buildSessionConfigRepairPrompt("garbled session")
	if !strings.Contains(sp, "garbled session") || !strings.Contains(sp, "sessions") {
		t.Errorf("session config repair prompt missing input or schema hint")
	}
	// The session schema must keep the critical extract rules guidance.
	if !strings.Contains(sp, "extract") {
		t.Error("session config repair prompt should emphasize extract rules")
	}
}
