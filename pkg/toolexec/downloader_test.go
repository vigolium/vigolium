package toolexec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func makeTestTGZ(t *testing.T, binaryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: binaryName, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func newTestDownloader(t *testing.T, archive []byte, expectedChecksum string) *Downloader {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	t.Cleanup(srv.Close)

	spec := ToolSpec{
		Name:          "tool",
		CacheSubdir:   "toolexec-test",
		UserAgent:     "test",
		ArchiveFormat: ArchiveTGZ,
		ResolveDownloadURL: func(context.Context, *Downloader, string) (string, error) {
			return srv.URL + "/tool.tgz", nil
		},
	}
	if expectedChecksum != "" {
		spec.ResolveChecksum = func(context.Context, *Downloader, string) (string, error) {
			return expectedChecksum, nil
		}
	}
	d, err := NewDownloader(spec, DownloadConfig{CacheDir: t.TempDir(), Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("NewDownloader: %v", err)
	}
	return d
}

func TestDownloaderChecksumVerification(t *testing.T) {
	content := []byte("#!/bin/sh\necho hi\n")
	archive := makeTestTGZ(t, "tool", content)
	sum := sha256.Sum256(archive)
	correct := hex.EncodeToString(sum[:])

	t.Run("matching checksum extracts the binary", func(t *testing.T) {
		d := newTestDownloader(t, archive, correct)
		cb, err := d.GetBinary(context.Background())
		if err != nil {
			t.Fatalf("GetBinary: %v", err)
		}
		got, err := os.ReadFile(cb.Path)
		if err != nil {
			t.Fatalf("read extracted binary: %v", err)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("extracted content mismatch: got %q", got)
		}
	})

	t.Run("mismatched checksum is rejected before extraction", func(t *testing.T) {
		d := newTestDownloader(t, archive, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		_, err := d.GetBinary(context.Background())
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("expected ErrChecksumMismatch, got %v", err)
		}
		if _, statErr := os.Stat(d.cacheDir + "/tool"); !os.IsNotExist(statErr) {
			t.Errorf("binary should not be written on checksum failure")
		}
	})

	t.Run("nil resolver skips verification", func(t *testing.T) {
		d := newTestDownloader(t, archive, "")
		if _, err := d.GetBinary(context.Background()); err != nil {
			t.Fatalf("GetBinary without checksum resolver: %v", err)
		}
	})
}
