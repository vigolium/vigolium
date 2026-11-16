package contentcoding

import (
	"bytes"
	"compress/flate"
	"errors"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

const plain = "<html><title>hello</title><body>decoded body</body></html>"

func encode(t *testing.T, coding string) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w interface {
		Write([]byte) (int, error)
		Close() error
	}
	switch coding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "raw-deflate":
		fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		w = fw
	case "br":
		w = brotli.NewWriter(&buf)
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		w = zw
	}
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeEveryCoding(t *testing.T) {
	for header, enc := range map[string]string{
		"gzip": "gzip", "GZip ": "gzip", "x-gzip": "gzip", "deflate": "deflate",
		"br": "br", "zstd": "zstd",
	} {
		got, err := Decode(header, encode(t, enc), 0)
		if err != nil || string(got) != plain {
			t.Errorf("%q: got %q, %v", header, got, err)
		}
	}
	// Servers commonly send headerless DEFLATE under "deflate".
	if got, err := Decode("deflate", encode(t, "raw-deflate"), 0); err != nil || string(got) != plain {
		t.Errorf("raw deflate: got %q, %v", got, err)
	}
}

func TestDecodeRefusesWhatItCannotDecode(t *testing.T) {
	if _, err := Decode("gzip", []byte(plain), 0); err == nil {
		t.Error("a plaintext body under gzip decoded")
	}
	if _, err := Decode("compress", encode(t, "gzip"), 0); err == nil {
		t.Error("an unsupported coding decoded")
	}
	if _, err := Decode("gzip, br", encode(t, "gzip"), 0); err == nil {
		t.Error("a stacked coding is not one layer")
	}
	if _, err := Decode("gzip", encode(t, "gzip"), 10); !errors.Is(err, ErrTooLarge) {
		t.Errorf("past the cap: %v, want ErrTooLarge", err)
	}
	if got, err := Decode("gzip", encode(t, "gzip"), int64(len(plain))); err != nil || string(got) != plain {
		t.Errorf("at the cap: %q, %v", got, err)
	}
}

func TestNewReaderPassesUnknownCodingsThrough(t *testing.T) {
	rc, err := NewReader("identity", bytes.NewReader([]byte(plain)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, _ = out.ReadFrom(rc)
	if out.String() != plain {
		t.Errorf("identity: %q", out.String())
	}
	if Supported("identity") || !Supported(" BR ") {
		t.Error("Supported")
	}
}
