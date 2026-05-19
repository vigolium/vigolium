package storage

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateKey(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		want    string
	}{
		{"ugc/source.zip", false, "ugc/source.zip"},
		{"native-scans/uuid-123/results.tar.gz", false, "native-scans/uuid-123/results.tar.gz"},
		{"simple.txt", false, "simple.txt"},

		// traversal attacks
		{"../other-project/ugc/secret.zip", true, ""},
		{"../../etc/passwd", true, ""},
		{"ugc/../../other-project/file.zip", true, ""},
		{"ugc/../../../etc/passwd", true, ""},
		{"native-scans/../../other-project/results.tar.gz", true, ""},
		{"..", true, ""},
		{"foo/..", true, ""},
		{"foo/../bar", false, "bar"}, // filepath.Clean normalizes this to "bar" — safe

		// backslash attempts
		{"ugc\\..\\..\\other", true, ""},

		// empty
		{"", true, ""},
	}

	for _, tt := range tests {
		got, err := ValidateKey(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ValidateKey(%q) = %q, nil; want error", tt.input, got)
			}
		} else {
			if err != nil {
				t.Errorf("ValidateKey(%q) error: %v", tt.input, err)
			} else if got != tt.want {
				t.Errorf("ValidateKey(%q) = %q; want %q", tt.input, got, tt.want)
			}
		}
	}
}

func TestValidateProjectUUID(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", false},
		{"my-project", false},
		{"00000000-0000-0000-0000-000000000001", false},

		// traversal attacks
		{"../other-project", true},
		{"foo/bar", true},
		{"foo\\bar", true},
		{"..", true},
		{"", true},
	}

	for _, tt := range tests {
		err := ValidateProjectUUID(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ValidateProjectUUID(%q) = nil; want error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ValidateProjectUUID(%q) error: %v", tt.input, err)
		}
	}
}

func TestIsGCSURI(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"gs://project/key", true},
		{"gcs://project/key", true},
		{"https://example.com/repo.git", false},
		{"/local/path", false},
		{"", false},
		{"gs", false},
	}
	for _, tt := range cases {
		if got := IsGCSURI(tt.input); got != tt.want {
			t.Errorf("IsGCSURI(%q) = %v; want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseGCSPath_AcceptsAlias(t *testing.T) {
	cases := []string{
		"gs://5fbb3b76-1e7b-4d2b-b8d2-7ad6f3eef511/ugc/source.zip",
		"gcs://5fbb3b76-1e7b-4d2b-b8d2-7ad6f3eef511/ugc/source.zip",
	}
	for _, uri := range cases {
		project, key, err := ParseGCSPath(uri)
		if err != nil {
			t.Errorf("ParseGCSPath(%q) error: %v", uri, err)
			continue
		}
		if project != "5fbb3b76-1e7b-4d2b-b8d2-7ad6f3eef511" {
			t.Errorf("ParseGCSPath(%q) project = %q; want canonical UUID", uri, project)
		}
		if key != "ugc/source.zip" {
			t.Errorf("ParseGCSPath(%q) key = %q; want ugc/source.zip", uri, key)
		}
	}
}

func TestNormalizeGCSURI(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"gcs://proj/key", "gs://proj/key"},
		{"gs://proj/key", "gs://proj/key"},
		{"/local/path", "/local/path"},
		{"", ""},
	}
	for _, tt := range cases {
		if got := NormalizeGCSURI(tt.in); got != tt.want {
			t.Errorf("NormalizeGCSURI(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func TestArchiveExt(t *testing.T) {
	cases := []struct {
		key, want string
	}{
		{"a.zip", ".zip"},
		{"foo/bar.ZIP", ".zip"},
		{"a.tar.gz", ".tar.gz"},
		{"a.tgz", ".tar.gz"},
		{"a.tar", ".tar"},
		{"unknown.bin", ".tar.gz"},
		{"", ".tar.gz"},
	}
	for _, tt := range cases {
		if got := archiveExt(tt.key); got != tt.want {
			t.Errorf("archiveExt(%q) = %q; want %q", tt.key, got, tt.want)
		}
	}
}

func TestExtractZip_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "src.zip")

	w, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	zw := zip.NewWriter(w)
	files := map[string]string{
		"top.txt":          "hello",
		"sub/nested.txt":   "world",
		"sub/dir/empty.go": "package x\n",
	}
	for name, body := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	_ = w.Close()

	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := extractZip(archivePath, dest); err != nil {
		t.Fatalf("extractZip: %v", err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q; want %q", name, got, want)
		}
	}
}

func TestExtractZip_BlocksTraversal(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "evil.zip")

	w, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	zw := zip.NewWriter(w)
	fw, err := zw.Create("../escape.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := fw.Write([]byte("pwned")); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	_ = w.Close()

	dest := filepath.Join(dir, "out")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := extractZip(archivePath, dest); err == nil {
		t.Fatalf("expected traversal error")
	}
}

func TestStripBucketPrefix(t *testing.T) {
	const bucket = "vigolium-artifact-dev"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "console gsutil-style URI is collapsed to project-relative",
			in:   "gs://vigolium-artifact-dev/b8052014-34b6-4b96-a12f-10ba95f23ff4/on-demand/file.zip",
			want: "gs://b8052014-34b6-4b96-a12f-10ba95f23ff4/on-demand/file.zip",
		},
		{
			name: "gcs:// alias works the same",
			in:   "gcs://vigolium-artifact-dev/proj/key",
			want: "gs://proj/key",
		},
		{
			name: "first segment that isn't the bucket stays unchanged",
			in:   "gs://b8052014-34b6-4b96-a12f-10ba95f23ff4/on-demand/file.zip",
			want: "gs://b8052014-34b6-4b96-a12f-10ba95f23ff4/on-demand/file.zip",
		},
		{
			name: "non-gs URI is returned as-is",
			in:   "https://example.com/file",
			want: "https://example.com/file",
		},
		{
			name: "empty bucket is a no-op",
			in:   "gs://vigolium-artifact-dev/key",
			want: "gs://vigolium-artifact-dev/key",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			b := bucket
			if tt.name == "empty bucket is a no-op" {
				b = ""
			}
			if got := StripBucketPrefix(tt.in, b); got != tt.want {
				t.Errorf("StripBucketPrefix(%q, %q) = %q; want %q", tt.in, b, got, tt.want)
			}
		})
	}
}

func TestParseGCSPath_RejectsTraversal(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"gs://project-uuid/ugc/source.zip", false},
		{"gs://project-uuid/native-scans/uuid/results.tar.gz", false},

		// project UUID traversal
		{"gs://../other-project/ugc/secret.zip", true},
		{"gs://foo/bar/../../other-project/file", true},

		// key traversal
		{"gs://project-uuid/../../etc/passwd", true},
		{"gs://project-uuid/../other-project/ugc/file.zip", true},
	}

	for _, tt := range tests {
		_, _, err := ParseGCSPath(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("ParseGCSPath(%q) = nil; want error", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("ParseGCSPath(%q) error: %v", tt.input, err)
		}
	}
}
