package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
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

// writeTar builds an in-memory tar from headers; a header whose Name has an
// entry in bodies gets that content.
func writeTar(t *testing.T, headers []tar.Header, bodies map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range headers {
		body, hasBody := bodies[h.Name]
		if hasBody {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if hasBody {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractTar_SymlinkCannotEscape is the regression for an archive that
// plants a symlink with an absolute target and then writes through it.
func TestExtractTar_SymlinkCannotEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	tmp := t.TempDir()
	outside := filepath.Join(tmp, "outside")
	dest := filepath.Join(tmp, "dest")
	for _, d := range []string{outside, dest} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	data := writeTar(t, []tar.Header{
		{Name: "app/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "app/evil", Typeflag: tar.TypeSymlink, Linkname: outside},
		{Name: "app/evil/pwned.txt", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "app/rel", Typeflag: tar.TypeSymlink, Linkname: "../../outside"},
		{Name: "app/ok", Typeflag: tar.TypeSymlink, Linkname: "main.go"},
		{Name: "app/main.go", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"app/evil/pwned.txt": "x", "app/main.go": "package main\n"})

	if err := extractTar(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extractTar: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Errorf("a file was written outside the destination through a symlink")
	}
	if fi, err := os.Lstat(filepath.Join(dest, "app", "evil")); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("a symlink with an absolute target was created")
	}
	if _, err := os.Lstat(filepath.Join(dest, "app", "rel")); err == nil {
		t.Errorf("a symlink whose relative target climbs out of the destination was created")
	}
	// An ordinary in-tree relative symlink must keep working.
	if got, err := os.Readlink(filepath.Join(dest, "app", "ok")); err != nil || got != "main.go" {
		t.Errorf("in-tree symlink: got %q, err %v; want %q", got, err, "main.go")
	}
}

// TestExtractTar_MasksFileMode pins that archive-chosen modes cannot make an
// extracted file group/world-writable.
func TestExtractTar_MasksFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dest := t.TempDir()
	data := writeTar(t, []tar.Header{
		{Name: "loose.sh", Typeflag: tar.TypeReg, Mode: 0o4777},
	}, map[string]string{"loose.sh": "#!/bin/sh\n"})

	if err := extractTar(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("extractTar: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dest, "loose.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		t.Errorf("extracted file is group/world-writable: %v", perm)
	}
	if fi.Mode()&os.ModeSetuid != 0 {
		t.Errorf("extracted file kept a setuid bit")
	}
}

func TestSafeArchivePath(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"app/main.go", filepath.Join("app", "main.go"), true},
		{"./app/../app/main.go", filepath.Join("app", "main.go"), true},
		{"/abs/file.txt", filepath.Join("abs", "file.txt"), true}, // leading slash stripped, as before
		{"../escape.txt", "", false},
		{"app/../../escape.txt", "", false},
		{"", "", false},
		{".", "", false},
	}
	for _, tc := range cases {
		got, ok := safeArchivePath(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("safeArchivePath(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestSymlinkStaysInside(t *testing.T) {
	cases := []struct {
		link, target string
		want         bool
	}{
		{filepath.Join("app", "ok"), "main.go", true},
		{filepath.Join("app", "sub", "up"), "../main.go", true},
		{filepath.Join("app", "evil"), "/etc", false},
		{filepath.Join("app", "rel"), "../../outside", false},
		{"top", "..", false},
		{"top", "", false},
	}
	for _, tc := range cases {
		if got := symlinkStaysInside(tc.link, tc.target); got != tc.want {
			t.Errorf("symlinkStaysInside(%q, %q) = %v, want %v", tc.link, tc.target, got, tc.want)
		}
	}
}
