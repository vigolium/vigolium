package responsechain

import (
	"bytes"
	"compress/zlib"
	"io"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	kgzip "github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

func TestWrapDecodeReader_Gzip(t *testing.T) {
	original := "Hello, gzip world! This is a test of gzip decompression."

	var buf bytes.Buffer
	gw, err := kgzip.NewWriterLevel(&buf, kgzip.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.Write([]byte(original)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	got := decompressAndRead(t, "gzip", buf.Bytes())
	if got != original {
		t.Errorf("gzip: got %q, want %q", got, original)
	}
}

func TestWrapDecodeReader_Deflate(t *testing.T) {
	original := "Hello, deflate world! This is a test of deflate decompression."

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(original)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got := decompressAndRead(t, "deflate", buf.Bytes())
	if got != original {
		t.Errorf("deflate: got %q, want %q", got, original)
	}
}

func TestWrapDecodeReader_Brotli(t *testing.T) {
	original := "Hello, brotli world! This is a test of brotli decompression."

	var buf bytes.Buffer
	bw := brotli.NewWriterLevel(&buf, brotli.DefaultCompression)
	if _, err := bw.Write([]byte(original)); err != nil {
		t.Fatal(err)
	}
	if err := bw.Close(); err != nil {
		t.Fatal(err)
	}

	got := decompressAndRead(t, "br", buf.Bytes())
	if got != original {
		t.Errorf("brotli: got %q, want %q", got, original)
	}
}

func TestWrapDecodeReader_Zstd(t *testing.T) {
	original := "Hello, zstd world! This is a test of zstd decompression."

	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write([]byte(original)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	got := decompressAndRead(t, "zstd", buf.Bytes())
	if got != original {
		t.Errorf("zstd: got %q, want %q", got, original)
	}
}

func TestWrapDecodeReader_NoEncoding(t *testing.T) {
	original := "Hello, plain world!"

	got := decompressAndRead(t, "", []byte(original))
	if got != original {
		t.Errorf("no-encoding: got %q, want %q", got, original)
	}
}

// decompressAndRead is a test helper that creates an http.Response with the
// given Content-Encoding and compressed body, passes it through wrapDecodeReader,
// and returns the decompressed string.
func decompressAndRead(t *testing.T, encoding string, compressed []byte) string {
	t.Helper()

	header := http.Header{}
	if encoding != "" {
		header.Set("Content-Encoding", encoding)
	}

	resp := &http.Response{
		Header: header,
		Body:   io.NopCloser(bytes.NewReader(compressed)),
	}

	rc, err := wrapDecodeReader(resp)
	if err != nil {
		t.Fatalf("wrapDecodeReader(%s) returned error: %v", encoding, err)
	}
	defer func() { _ = rc.Close() }()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading decompressed %s body: %v", encoding, err)
	}
	return string(got)
}
