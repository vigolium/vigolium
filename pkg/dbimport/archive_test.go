package dbimport

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveExt(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"bundle.tar.gz", ".tar.gz"},
		{"bundle.TAR.GZ", ".tar.gz"}, // case-insensitive
		{"bundle.tgz", ".tgz"},
		{"bundle.zip", ".zip"},
		{"export.jsonl", ".jsonl"},
		{"export.ndjson", ".ndjson"},
		{"export.json", ".json"},
		{"/path/to/archive.zip", ".zip"},
		{"noext", ""},
		{"archive.rar", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := ArchiveExt(tt.path); got != tt.want {
				t.Errorf("ArchiveExt(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// writeTarGz builds a .tar.gz at path containing the given name->content files.
func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar.gz: %v", err)
	}
	defer func() { _ = f.Close() }()
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
}

// writeZip builds a .zip at path containing the given name->content files.
func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = f.Close() }()
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create entry: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

func TestExtractArchiveToDirTarGz(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "bundle.tar.gz")
	writeTarGz(t, archive, map[string]string{
		"a.txt":     "hello",
		"sub/b.txt": "world",
	})

	out, cleanup, err := ExtractArchiveToDir(archive)
	if err != nil {
		t.Fatalf("ExtractArchiveToDir: %v", err)
	}
	defer cleanup()

	assertFileContent(t, filepath.Join(out, "a.txt"), "hello")
	assertFileContent(t, filepath.Join(out, "sub", "b.txt"), "world")
}

func TestExtractArchiveToDirZip(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "bundle.zip")
	writeZip(t, archive, map[string]string{
		"x.json":       `{"k":1}`,
		"nested/y.txt": "deep",
	})

	out, cleanup, err := ExtractArchiveToDir(archive)
	if err != nil {
		t.Fatalf("ExtractArchiveToDir: %v", err)
	}
	defer cleanup()

	assertFileContent(t, filepath.Join(out, "x.json"), `{"k":1}`)
	assertFileContent(t, filepath.Join(out, "nested", "y.txt"), "deep")
}

func TestExtractArchiveUnsupportedExt(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "data.rar")
	if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := ExtractArchiveToDir(bad)
	defer cleanup()
	if err == nil {
		t.Fatal("expected error for unsupported extension, got nil")
	}
}

// TestExtractRejectsPathTraversal guards the zip-slip / tar-slip defense: an
// archive entry that escapes the destination directory must be rejected.
func TestExtractRejectsPathTraversal(t *testing.T) {
	t.Run("zip", func(t *testing.T) {
		dir := t.TempDir()
		archive := filepath.Join(dir, "evil.zip")
		writeZip(t, archive, map[string]string{
			"../escape.txt": "pwned",
		})
		_, cleanup, err := ExtractArchiveToDir(archive)
		defer cleanup()
		if err == nil {
			t.Fatal("expected path-traversal rejection, got nil error")
		}
	})
	t.Run("tar.gz", func(t *testing.T) {
		dir := t.TempDir()
		archive := filepath.Join(dir, "evil.tar.gz")
		writeTarGz(t, archive, map[string]string{
			"../escape.txt": "pwned",
		})
		_, cleanup, err := ExtractArchiveToDir(archive)
		defer cleanup()
		if err == nil {
			t.Fatal("expected path-traversal rejection, got nil error")
		}
	})
}

func TestCopyDirContents(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "nested.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := CopyDirContents(src, dst); err != nil {
		t.Fatalf("CopyDirContents: %v", err)
	}
	assertFileContent(t, filepath.Join(dst, "top.txt"), "top")
	assertFileContent(t, filepath.Join(dst, "sub", "nested.txt"), "nested")
}

func TestCopyDirContentsRejectsNonDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CopyDirContents(file, filepath.Join(dir, "out")); err == nil {
		t.Fatal("expected error when source is not a directory")
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("%s = %q, want %q", path, got, want)
	}
}
