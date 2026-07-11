// Package grpcweb is a dependency-free gRPC-Web (HTTP/1.1) frame codec.
//
// gRPC-Web multiplexes length-prefixed messages over a normal HTTP/1.1 body so
// browsers can speak gRPC without HTTP/2 trailers. Each frame is a 5-byte header
// (1 flag byte + 4-byte big-endian message length) followed by the message
// bytes. The high bit of the flag byte (0x80) marks a *trailer* frame whose body
// is an HTTP/1-style "key: value\r\n" block carrying grpc-status / grpc-message.
//
// This package deliberately depends on nothing outside the standard library. It
// does NOT link google.golang.org/grpc or google.golang.org/protobuf and it does
// NOT decode protobuf message payloads — only the gRPC-Web framing envelope. Full
// protobuf descriptor decoding and native HTTP/2 gRPC support are explicit
// follow-ups (see pkg/modules/active/grpc_surface_audit for the tracking notes)
// that would require those two modules; keep them out of here.
package grpcweb

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	// flagData marks a normal (message) frame.
	flagData byte = 0x00
	// flagTrailer marks a trailer frame (grpc-status / grpc-message block).
	flagTrailer byte = 0x80
	// headerLen is the fixed gRPC-Web frame header size (1 flag + 4 length).
	headerLen = 5
)

// ErrShortFrame is the sentinel returned by DecodeFrames / DecodeBody when the
// body ends in the middle of a frame (a truncated trailing frame). Any complete
// frames parsed before the truncation are still returned alongside it, so callers
// can decode best-effort without panicking. Compare with errors.Is.
var ErrShortFrame = errors.New("grpcweb: truncated trailing frame")

// Frame is a single decoded gRPC-Web frame. Data holds the raw message bytes
// (still protobuf-encoded for data frames; the raw trailer block for trailers).
type Frame struct {
	Trailer bool
	Data    []byte
}

// EncodeFrame builds one gRPC-Web frame: a 5-byte header (flag 0x00 for a data
// frame, 0x80 for a trailer) plus the big-endian message length, followed by msg.
func EncodeFrame(trailer bool, msg []byte) []byte {
	flag := flagData
	if trailer {
		flag = flagTrailer
	}
	out := make([]byte, headerLen+len(msg))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:headerLen], uint32(len(msg)))
	copy(out[headerLen:], msg)
	return out
}

// DecodeFrames parses a concatenation of gRPC-Web frames. A truncated trailing
// frame (a header that runs past the end, or a body shorter than its declared
// length) is tolerated: every complete frame parsed so far is returned together
// with ErrShortFrame instead of panicking. A clean parse returns a nil error.
func DecodeFrames(body []byte) ([]Frame, error) {
	var frames []Frame
	for i := 0; i < len(body); {
		// Not enough bytes left for a full 5-byte header → truncated tail.
		if i+headerLen > len(body) {
			return frames, ErrShortFrame
		}
		flag := body[i]
		n := int(binary.BigEndian.Uint32(body[i+1 : i+headerLen]))
		start := i + headerLen
		end := start + n
		// Declared length runs past the buffer → truncated message; keep the
		// complete frames we already have and signal the truncation.
		if n < 0 || end > len(body) {
			return frames, ErrShortFrame
		}
		frames = append(frames, Frame{
			Trailer: flag&flagTrailer != 0,
			Data:    append([]byte(nil), body[start:end]...),
		})
		i = end
	}
	return frames, nil
}

// ParseTrailer parses a trailer frame body — an HTTP/1-style block of
// "key: value" lines delimited by CRLF (bare LF tolerated). It returns the
// grpc-status and grpc-message values (empty when absent) plus the full set of
// lowercased header keys. Keys are compared case-insensitively.
func ParseTrailer(f Frame) (status string, message string, headers map[string]string) {
	headers = make(map[string]string)
	for _, line := range strings.Split(string(f.Data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		headers[key] = val
	}
	return headers["grpc-status"], headers["grpc-message"], headers
}

// IsGRPCWebContentType reports whether ct is a gRPC-Web media type and, if so,
// whether it uses the text (base64) framing. It recognizes application/grpc-web,
// application/grpc-web+proto, application/grpc-web-text and
// application/grpc-web-text+proto. Media-type parameters (e.g. ";charset=utf-8")
// are ignored. text is true when the "-text" variant is used, meaning the body
// is base64-encoded and must be decoded before framing (see DecodeBody).
func IsGRPCWebContentType(ct string) (ok bool, text bool) {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if !strings.HasPrefix(ct, "application/grpc-web") {
		return false, false
	}
	return true, strings.Contains(ct, "grpc-web-text")
}

// DecodeBody decodes a full gRPC-Web response body into frames, honoring the
// content type: text (base64) bodies are base64-decoded first, then framed.
// Non-text bodies are framed directly. It is best-effort — a truncated tail is
// reported via ErrShortFrame with the complete frames still returned.
func DecodeBody(ct string, body []byte) ([]Frame, error) {
	if _, text := IsGRPCWebContentType(ct); text {
		raw := strings.TrimSpace(string(body))
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			// Some encoders omit padding; retry with the raw (unpadded) alphabet.
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "="))
			if err != nil {
				return nil, err
			}
		}
		body = decoded
	}
	return DecodeFrames(body)
}

// GRPCStatus returns the grpc-status code carried by the first trailer frame in
// frames, if any. ok is false when no trailer frame declares a grpc-status.
func GRPCStatus(frames []Frame) (code string, ok bool) {
	for _, f := range frames {
		if !f.Trailer {
			continue
		}
		if status, _, _ := ParseTrailer(f); status != "" {
			return status, true
		}
	}
	return "", false
}

// IsRPCPath reports whether path has the gRPC method shape "/package.Service/Method":
// exactly two segments, the first a dotted fully-qualified service name and the
// second a bare method identifier. It is a cheap heuristic used by the gRPC-Web
// modules to recognize an RPC endpoint from its URL alone.
func IsRPCPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 2 {
		return false
	}
	svc, method := parts[0], parts[1]
	if svc == "" || method == "" {
		return false
	}
	// The service must be a dotted, fully-qualified name (package.Service); this
	// discriminates gRPC paths from ordinary two-segment REST paths (/api/users).
	if !strings.Contains(svc, ".") {
		return false
	}
	return isIdentifier(strings.ReplaceAll(svc, ".", "")) && isIdentifier(method)
}

// isIdentifier reports whether s is a non-empty run of ASCII letters, digits and
// underscores (the character set of protobuf identifiers, dots already removed).
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}
