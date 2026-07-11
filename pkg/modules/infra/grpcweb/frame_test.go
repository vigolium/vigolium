package grpcweb

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	msg := []byte("hello-rpc-payload")
	trailer := []byte("grpc-status:0\r\ngrpc-message:OK\r\n")

	body := append(EncodeFrame(false, msg), EncodeFrame(true, trailer)...)

	frames, err := DecodeFrames(body)
	require.NoError(t, err)
	require.Len(t, frames, 2)

	assert.False(t, frames[0].Trailer)
	assert.Equal(t, msg, frames[0].Data)
	assert.True(t, frames[1].Trailer)
	assert.Equal(t, trailer, frames[1].Data)
}

func TestEncodeFrameHeader(t *testing.T) {
	t.Parallel()

	// Empty data frame: 5-byte header, flag 0x00, length 0.
	empty := EncodeFrame(false, nil)
	require.Len(t, empty, 5)
	assert.Equal(t, byte(0x00), empty[0])
	assert.Equal(t, []byte{0, 0, 0, 0}, empty[1:5])

	// Trailer flag sets the high bit and the length reflects the payload.
	tr := EncodeFrame(true, []byte("ab"))
	require.Len(t, tr, 7)
	assert.Equal(t, byte(0x80), tr[0])
	assert.Equal(t, []byte{0, 0, 0, 2}, tr[1:5])
}

func TestParseTrailer(t *testing.T) {
	t.Parallel()

	f := Frame{Trailer: true, Data: []byte("grpc-status:3\r\ngrpc-message:invalid argument\r\ncustom-key: v1\r\n")}
	status, message, headers := ParseTrailer(f)
	assert.Equal(t, "3", status)
	assert.Equal(t, "invalid argument", message)
	assert.Equal(t, "v1", headers["custom-key"])
}

func TestParseTrailerBareLF(t *testing.T) {
	t.Parallel()

	// Tolerate bare LF line endings (no CR).
	f := Frame{Trailer: true, Data: []byte("grpc-status:7\ngrpc-message:denied\n")}
	status, message, _ := ParseTrailer(f)
	assert.Equal(t, "7", status)
	assert.Equal(t, "denied", message)
}

func TestIsGRPCWebContentType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ct       string
		wantOK   bool
		wantText bool
	}{
		{"application/grpc-web", true, false},
		{"application/grpc-web+proto", true, false},
		{"application/grpc-web-text", true, true},
		{"application/grpc-web-text+proto", true, true},
		{"application/grpc-web+proto; charset=utf-8", true, false},
		{"APPLICATION/GRPC-WEB-TEXT", true, true},
		{"application/json", false, false},
		{"text/html", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		ok, text := IsGRPCWebContentType(c.ct)
		assert.Equal(t, c.wantOK, ok, "ok for %q", c.ct)
		assert.Equal(t, c.wantText, text, "text for %q", c.ct)
	}
}

func TestDecodeBodyText(t *testing.T) {
	t.Parallel()

	msg := []byte("payload")
	trailer := []byte("grpc-status:0\r\n")
	raw := append(EncodeFrame(false, msg), EncodeFrame(true, trailer)...)
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))

	frames, err := DecodeBody("application/grpc-web-text", encoded)
	require.NoError(t, err)
	require.Len(t, frames, 2)
	assert.Equal(t, msg, frames[0].Data)

	code, ok := GRPCStatus(frames)
	require.True(t, ok)
	assert.Equal(t, "0", code)
}

func TestDecodeBodyBinary(t *testing.T) {
	t.Parallel()

	raw := append(EncodeFrame(false, []byte("x")), EncodeFrame(true, []byte("grpc-status:5\r\n"))...)
	frames, err := DecodeBody("application/grpc-web+proto", raw)
	require.NoError(t, err)
	require.Len(t, frames, 2)

	code, ok := GRPCStatus(frames)
	require.True(t, ok)
	assert.Equal(t, "5", code)
}

func TestDecodeFramesTruncatedTolerance(t *testing.T) {
	t.Parallel()

	full := EncodeFrame(false, []byte("complete"))

	// Case 1: a complete frame followed by a partial header (< 5 bytes).
	body := append(append([]byte(nil), full...), 0x00, 0x00)
	frames, err := DecodeFrames(body)
	assert.True(t, errors.Is(err, ErrShortFrame))
	require.Len(t, frames, 1)
	assert.Equal(t, []byte("complete"), frames[0].Data)

	// Case 2: a complete frame followed by a header claiming more bytes than exist.
	partial := EncodeFrame(false, []byte("truncated-message"))
	partial = partial[:len(partial)-5] // chop the tail of the message
	body2 := append(append([]byte(nil), full...), partial...)
	frames2, err2 := DecodeFrames(body2)
	assert.True(t, errors.Is(err2, ErrShortFrame))
	require.Len(t, frames2, 1)
	assert.Equal(t, []byte("complete"), frames2[0].Data)
}

func TestGRPCStatusAbsent(t *testing.T) {
	t.Parallel()

	// Only a data frame, no trailer → no status.
	frames := []Frame{{Trailer: false, Data: []byte("data")}}
	_, ok := GRPCStatus(frames)
	assert.False(t, ok)
}

func TestIsRPCPath(t *testing.T) {
	t.Parallel()

	assert.True(t, IsRPCPath("/pkg.Svc/GetThing"))
	assert.True(t, IsRPCPath("/grpc.health.v1.Health/Check"))
	assert.True(t, IsRPCPath("/a.b.c.Service/Method_2"))
	assert.False(t, IsRPCPath("/api/users"))       // first segment has no dot
	assert.False(t, IsRPCPath("/pkg.Svc/a/b"))     // too many segments
	assert.False(t, IsRPCPath("/pkg.Svc"))         // missing method
	assert.False(t, IsRPCPath("pkg.Svc/Method"))   // no leading slash
	assert.False(t, IsRPCPath("/pkg.Svc/Get-Bad")) // hyphen not an identifier char
}
