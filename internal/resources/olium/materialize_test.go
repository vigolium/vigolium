package olium

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOnDiskWritesThenPreservesEdits(t *testing.T) {
	dir := t.TempDir()

	// First call materializes the embedded skills.
	n, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("EnsureOnDisk: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one skill file written")
	}

	// A known built-in must have landed at <dir>/<name>/SKILL.md.
	target := filepath.Join(dir, "idor-blast-radius", "SKILL.md")
	if _, statErr := os.Stat(target); statErr != nil {
		t.Fatalf("expected materialized skill at %s: %v", target, statErr)
	}

	// Edit it, then re-run: write-if-missing must NOT clobber the edit.
	const edit = "EDITED BY OPERATOR\n"
	if err := os.WriteFile(target, []byte(edit), 0o644); err != nil {
		t.Fatal(err)
	}
	n2, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("EnsureOnDisk (2nd): %v", err)
	}
	if n2 != 0 {
		t.Fatalf("2nd call wrote %d files; expected 0 (all present)", n2)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != edit {
		t.Fatalf("operator edit was clobbered: got %q", string(got))
	}
}

func TestEnsureOnDiskEmptyDir(t *testing.T) {
	if _, err := EnsureOnDisk(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}
