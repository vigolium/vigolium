package agent

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/gitutil"
)

func TestIsGitURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://github.com/org/repo.git", true},
		{"https://github.com/org/repo", true},
		{"http://github.com/org/repo.git", true},
		{"https://oauth2:ghp_abc123@github.com/org/repo.git", true},
		{"git@github.com:org/repo.git", true},
		{"git@gitlab.com:org/repo.git", true},
		{"/home/user/src/app", false},
		{"~/src/app", false},
		{"./relative/path", false},
		{"/tmp/app.tar.gz", false},
		{"app.zip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := gitutil.LooksLikeGitURL(tt.input)
			if got != tt.want {
				t.Errorf("LooksLikeGitURL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsArchive(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"app.zip", true},
		{"source.tar.gz", true},
		{"source.tgz", true},
		{"source.tar.bz2", true},
		{"source.tbz2", true},
		{"source.tar.xz", true},
		{"source.txz", true},
		{"SOURCE.ZIP", true}, // case insensitive
		{"App.TAR.GZ", true}, // case insensitive
		{"/path/to/app.zip", true},
		{"~/downloads/source.tgz", true},
		{"app.go", false},
		{"README.md", false},
		{"/home/user/src", false},
		{"", false},
		{"https://github.com/org/repo.git", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isArchive(tt.input)
			if got != tt.want {
				t.Errorf("isArchive(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeGitURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			"https://oauth2:ghp_abc123@github.com/org/repo.git",
			"https://***@github.com/org/repo.git",
		},
		{
			"https://x-access-token:ghs_secret@github.com/org/repo.git",
			"https://***@github.com/org/repo.git",
		},
		{
			"https://github.com/org/repo.git",
			"https://github.com/org/repo.git",
		},
		{
			"git@github.com:org/repo.git",
			"git@github.com:org/repo.git",
		},
		{
			"http://token@gitlab.com/org/repo.git",
			"http://***@gitlab.com/org/repo.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeGitURL(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeGitURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractTokenFromURL(t *testing.T) {
	tests := []struct {
		input     string
		wantURL   string
		wantToken string
	}{
		{
			"https://oauth2:ghp_token123@github.com/org/repo.git",
			"https://github.com/org/repo.git",
			"ghp_token123",
		},
		{
			"https://x-access-token:ghs_secret@github.com/org/repo.git",
			"https://github.com/org/repo.git",
			"ghs_secret",
		},
		{
			"https://github.com/org/repo.git",
			"https://github.com/org/repo.git",
			"",
		},
		{
			"git@github.com:org/repo.git",
			"git@github.com:org/repo.git",
			"",
		},
		{
			// PR URL with embedded token — token should be extracted
			"https://oauth2:ghp_prtoken@github.com/org/repo/pull/42",
			"https://github.com/org/repo/pull/42",
			"ghp_prtoken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotURL, gotToken := extractTokenFromURL(tt.input)
			if gotURL != tt.wantURL {
				t.Errorf("extractTokenFromURL(%q) URL = %q, want %q", tt.input, gotURL, tt.wantURL)
			}
			if gotToken != tt.wantToken {
				t.Errorf("extractTokenFromURL(%q) token = %q, want %q", tt.input, gotToken, tt.wantToken)
			}
		})
	}
}

func TestGitHubPRPatternMatch(t *testing.T) {
	// Verify the regex correctly matches GitHub PR URLs
	tests := []struct {
		input string
		match bool
	}{
		{"https://github.com/org/repo/pull/123", true},
		{"https://github.com/org/repo/pull/1", true},
		{"http://github.com/org/repo/pull/42", true},
		{"main...feature-branch", false},
		{"HEAD~5", false},
		{"https://gitlab.com/org/repo/-/merge_requests/7", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := githubPRPattern.MatchString(tt.input)
			if got != tt.match {
				t.Errorf("githubPRPattern.MatchString(%q) = %v, want %v", tt.input, got, tt.match)
			}
		})
	}
}

func TestParseChangedFiles(t *testing.T) {
	input := "src/main.go\nlib/utils.go\n\nREADME.md\n"
	got := parseChangedFiles(input)
	want := []string{"src/main.go", "lib/utils.go", "README.md"}

	if len(got) != len(want) {
		t.Fatalf("parseChangedFiles got %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseChangedFiles[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseDiffFileNames(t *testing.T) {
	input := `diff --git a/src/main.go b/src/main.go
--- a/src/main.go
+++ b/src/main.go
@@ -1,3 +1,5 @@
 package main
+import "fmt"
diff --git a/lib/utils.go b/lib/utils.go
--- a/lib/utils.go
+++ b/lib/utils.go
@@ -1 +1,2 @@
 package lib
+func Help() {}
`
	got := parseDiffFileNames(input)
	want := []string{"src/main.go", "lib/utils.go"}

	if len(got) != len(want) {
		t.Fatalf("parseDiffFileNames got %d files, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseDiffFileNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDetectEffectiveRoot(t *testing.T) {
	// Case 1: Single root directory
	dir := t.TempDir()
	subDir := filepath.Join(dir, "app-v1")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := detectEffectiveRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != subDir {
		t.Errorf("detectEffectiveRoot (single root) = %q, want %q", got, subDir)
	}

	// Case 2: Multiple entries — returns dir itself
	dir2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir2, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir2, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}

	got2, err := detectEffectiveRoot(dir2)
	if err != nil {
		t.Fatal(err)
	}
	if got2 != dir2 {
		t.Errorf("detectEffectiveRoot (multiple) = %q, want %q", got2, dir2)
	}

	// Case 3: Single dir + file — returns dir itself
	dir3 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir3, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir3, "README.md"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	got3, err := detectEffectiveRoot(dir3)
	if err != nil {
		t.Fatal(err)
	}
	if got3 != dir3 {
		t.Errorf("detectEffectiveRoot (dir + file) = %q, want %q", got3, dir3)
	}
}

func TestExtractZip(t *testing.T) {
	// Create a test zip in a temp dir
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")

	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)

	// Add a file inside a directory
	fw, err := zw.Create("myapp/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("package main\nfunc main() {}\n")); err != nil {
		t.Fatal(err)
	}

	fw2, err := zw.Create("myapp/lib/utils.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw2.Write([]byte("package lib\n")); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}

	// Extract
	destDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := extractZip(zipPath, destDir); err != nil {
		t.Fatal(err)
	}

	// Verify files exist
	mainPath := filepath.Join(destDir, "myapp", "main.go")
	if _, err := os.Stat(mainPath); err != nil {
		t.Errorf("expected %s to exist", mainPath)
	}

	utilsPath := filepath.Join(destDir, "myapp", "lib", "utils.go")
	if _, err := os.Stat(utilsPath); err != nil {
		t.Errorf("expected %s to exist", utilsPath)
	}
}

func TestExtractTarGz(t *testing.T) {
	tmpDir := t.TempDir()
	tgzPath := filepath.Join(tmpDir, "test.tar.gz")

	// Create tar.gz
	f, err := os.Create(tgzPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Add directory
	if err := tw.WriteHeader(&tar.Header{
		Name:     "myapp/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	}); err != nil {
		t.Fatal(err)
	}

	// Add file
	content := []byte("package main\nfunc main() {}\n")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "myapp/main.go",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Extract
	destDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(tgzPath, destDir); err != nil {
		t.Fatal(err)
	}

	// Verify
	mainPath := filepath.Join(destDir, "myapp", "main.go")
	if _, err := os.Stat(mainPath); err != nil {
		t.Errorf("expected %s to exist", mainPath)
	}
}

func TestResolveSource_LocalPath(t *testing.T) {
	tmpDir := t.TempDir()
	sessionDir := t.TempDir()

	resolved, err := ResolveSource(tmpDir, sessionDir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil {
		t.Fatal("expected non-nil resolved source")
	}
	if resolved.LocalPath != tmpDir {
		t.Errorf("LocalPath = %q, want %q", resolved.LocalPath, tmpDir)
	}
	if resolved.LocalPath != tmpDir {
		t.Errorf("expected LocalPath=%q, got %q", tmpDir, resolved.LocalPath)
	}
}

func TestResolveSource_Empty(t *testing.T) {
	resolved, err := ResolveSource("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if resolved != nil {
		t.Error("expected nil for empty source path")
	}
}

func TestResolveSource_NonexistentPath(t *testing.T) {
	_, err := ResolveSource("/nonexistent/path/that/does/not/exist", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestResolveSource_Archive(t *testing.T) {
	tmpDir := t.TempDir()
	sessionDir := t.TempDir()

	// Create a zip archive
	zipPath := filepath.Join(tmpDir, "source.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	fw, err := zw.Create("app/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("package main")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zf.Close(); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveSource(zipPath, sessionDir)
	if err != nil {
		t.Fatal(err)
	}
	// Should detect single root "app"
	if filepath.Base(resolved.LocalPath) != "app" {
		t.Errorf("expected single-root detection, got LocalPath=%q", resolved.LocalPath)
	}
	// Verify file exists
	mainPath := filepath.Join(resolved.LocalPath, "main.go")
	if _, err := os.Stat(mainPath); err != nil {
		t.Errorf("expected %s to exist", mainPath)
	}
}

func TestResolveDiff_Empty(t *testing.T) {
	src, dc, err := ResolveDiff("", 0, "/some/path", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if dc != nil {
		t.Error("expected nil DiffContext for empty diff arg")
	}
	if src != "/some/path" {
		t.Errorf("expected source path passthrough, got %q", src)
	}
}

func TestResolveDiff_LastCommitsConverts(t *testing.T) {
	// lastCommits without source should error (since HEAD~5 needs a git repo)
	_, _, err := ResolveDiff("", 5, "", t.TempDir())
	if err == nil {
		t.Error("expected error when using --last-commits without --source")
	}
}

func TestResolveDiff_GitRefWithoutSource(t *testing.T) {
	_, _, err := ResolveDiff("main...feature", 0, "", t.TempDir())
	if err == nil {
		t.Error("expected error for git ref range without source")
	}
}
