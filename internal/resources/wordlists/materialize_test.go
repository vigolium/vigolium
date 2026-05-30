package wordlists

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOnDisk_WritesAllListsWithEmbeddedContent(t *testing.T) {
	dir := t.TempDir()

	paths, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("EnsureOnDisk: %v", err)
	}

	cases := []struct {
		name string
		got  string
	}{
		{"file-short.txt", paths.ShortFile},
		{"file-long.txt", paths.LongFile},
		{"dir-short.txt", paths.ShortDir},
		{"dir-long.txt", paths.LongDir},
		{"fuzz.txt", paths.Fuzz},
	}
	for _, c := range cases {
		if c.got != filepath.Join(dir, c.name) {
			t.Errorf("%s: path = %q, want %q", c.name, c.got, filepath.Join(dir, c.name))
		}
		onDisk, err := os.ReadFile(c.got)
		if err != nil {
			t.Fatalf("read %s: %v", c.got, err)
		}
		embedded, err := WordlistsFS.ReadFile(c.name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", c.name, err)
		}
		if len(onDisk) != len(embedded) {
			t.Errorf("%s: on-disk size %d != embedded size %d", c.name, len(onDisk), len(embedded))
		}
		if len(onDisk) == 0 {
			t.Errorf("%s: materialized file is empty", c.name)
		}
	}
}

func TestEnsureOnDisk_IsIdempotentAndRepairsTampering(t *testing.T) {
	dir := t.TempDir()

	first, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("first EnsureOnDisk: %v", err)
	}

	// A second call must succeed and return the same paths without re-erroring.
	second, err := EnsureOnDisk(dir)
	if err != nil {
		t.Fatalf("second EnsureOnDisk: %v", err)
	}
	if first != second {
		t.Errorf("paths changed across calls: %+v vs %+v", first, second)
	}

	// Corrupt a file (size mismatch) and confirm the next call rewrites it from
	// the embedded copy.
	if err := os.WriteFile(first.ShortFile, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := EnsureOnDisk(dir); err != nil {
		t.Fatalf("repair EnsureOnDisk: %v", err)
	}
	repaired, err := os.ReadFile(first.ShortFile)
	if err != nil {
		t.Fatalf("read repaired: %v", err)
	}
	embedded, _ := WordlistsFS.ReadFile("file-short.txt")
	if len(repaired) != len(embedded) {
		t.Errorf("tampered file not repaired: size %d != embedded %d", len(repaired), len(embedded))
	}
}
