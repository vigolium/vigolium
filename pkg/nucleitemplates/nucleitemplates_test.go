package nucleitemplates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "nuclei-templates-10.0.1/", Typeflag: tar.TypeDir, Mode: 0o755})
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// TestInstall is RUN-11: the pinned release archive is fetched over HTTP (no
// git), verified, unpacked without its top-level directory, marked, and a
// digest mismatch leaves the existing install untouched.
func TestInstall(t *testing.T) {
	archive := tarball(t, map[string]string{
		"nuclei-templates-10.0.1/http/cves/a.yaml": "id: a\n",
		"nuclei-templates-10.0.1/../escape.yaml":   "id: x\n",
	})
	sum := sha256.Sum256(archive)
	digest := hex.EncodeToString(sum[:])
	var fetched []string
	restore := SetFetcherForTest(func(_ context.Context, url string) (io.ReadCloser, error) {
		fetched = append(fetched, url)
		return io.NopCloser(bytes.NewReader(archive)), nil
	}, func(context.Context) (string, error) { return "v10.0.1", nil })
	defer restore()

	dir := filepath.Join(t.TempDir(), "nuclei-templates")
	m, err := Install(context.Background(), dir, Pin{Version: "v10.0.1", SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 1 || !strings.HasSuffix(fetched[0], "/archive/refs/tags/v10.0.1.tar.gz") {
		t.Fatalf("fetched %v", fetched)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "http", "cves", "a.yaml")); err != nil || string(data) != "id: a\n" {
		t.Fatalf("template not unpacked: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.yaml")); err == nil {
		t.Fatal("a ../ entry escaped the destination")
	}
	got, err := ReadMarker(dir)
	if err != nil || got.Version != "v10.0.1" || got.SHA256 != digest || m.InstalledAt.IsZero() {
		t.Fatalf("marker = %+v %v", got, err)
	}

	// Pinned digest mismatch: refused, the existing install stays.
	if _, err := Install(context.Background(), dir, Pin{Version: "v10.0.1", SHA256: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "http", "cves", "a.yaml")); err != nil {
		t.Fatal("a failed install removed the existing templates")
	}

	// No version: the latest release is resolved.
	fetched = nil
	if m, err := Install(context.Background(), dir, Pin{}); err != nil || m.Version != "v10.0.1" {
		t.Fatalf("latest install = %+v %v", m, err)
	}
}
