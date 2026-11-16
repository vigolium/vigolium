// Package contentcoding removes one HTTP content-coding (RFC 9110 §8.4.1)
// layer from a body: gzip (and its x-gzip alias), deflate, br and zstd. The
// coding names are the IANA HTTP Content Coding registry's, matched exactly
// after case folding — a protocol vocabulary, not a guess about the bytes.
//
// The response normaliser (pkg/deparos/responsechain) decodes wire bodies
// through NewReader, and the store (pkg/database) decodes ingested bodies
// through Decode, so a body reads the same whichever path it took.
package contentcoding

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

// Normalize folds a Content-Encoding value for matching: trimmed, lower
// case. A value listing several codings ("gzip, br") is returned whole.
func Normalize(coding string) string {
	return strings.ToLower(strings.TrimSpace(coding))
}

// Supported reports whether coding (one name, any case) is a coding this
// package decodes.
func Supported(coding string) bool {
	switch Normalize(coding) {
	case "gzip", "x-gzip", "deflate", "br", "zstd":
		return true
	}
	return false
}

// NewReader wraps r in a decoder for coding. An empty, "identity" or unknown
// coding returns r unchanged (wrapped to a ReadCloser), so a caller can pass
// any header value through. deflate is the zlib-wrapped form RFC 9110 names.
func NewReader(coding string, r io.Reader) (io.ReadCloser, error) {
	switch Normalize(coding) {
	case "gzip", "x-gzip":
		return gzip.NewReader(r)
	case "deflate":
		return zlib.NewReader(r)
	case "br":
		return io.NopCloser(brotli.NewReader(r)), nil
	case "zstd":
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	}
	if rc, ok := r.(io.ReadCloser); ok {
		return rc, nil
	}
	return io.NopCloser(r), nil
}

// ErrTooLarge is returned by Decode when the decoded body exceeds its cap.
var ErrTooLarge = errors.New("decoded body exceeds the size cap")

// Decode removes one coding layer from body, reading at most maxDecoded bytes
// of output (0 = no cap). It fails on an unsupported coding, on bytes that do
// not decode, on a stream that does not reach its end, and with ErrTooLarge
// past the cap — a caller storing the result keeps the original on any error
// rather than a fragment. "deflate" also accepts a raw (headerless) DEFLATE
// stream, which servers commonly send under that name.
func Decode(coding string, body []byte, maxDecoded int64) ([]byte, error) {
	name := Normalize(coding)
	if !Supported(name) {
		return nil, fmt.Errorf("unsupported content-coding %q", coding)
	}
	out, err := decodeWith(name, body, maxDecoded)
	if err != nil && name == "deflate" && !errors.Is(err, ErrTooLarge) {
		if raw, rawErr := readCapped(flate.NewReader(bytes.NewReader(body)), maxDecoded); rawErr == nil {
			return raw, nil
		}
	}
	return out, err
}

func decodeWith(name string, body []byte, maxDecoded int64) ([]byte, error) {
	rc, err := NewReader(name, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return readCapped(rc, maxDecoded)
}

// readCapped reads r to EOF, failing past maxDecoded bytes (0 = no cap).
func readCapped(r io.Reader, maxDecoded int64) ([]byte, error) {
	if maxDecoded <= 0 {
		return io.ReadAll(r)
	}
	out, err := io.ReadAll(io.LimitReader(r, maxDecoded+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > maxDecoded {
		return nil, ErrTooLarge
	}
	return out, nil
}
