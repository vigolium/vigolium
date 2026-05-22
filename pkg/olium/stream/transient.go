package stream

import "strings"

// TransientErrSubstrings matches provider stream/HTTP errors that are
// worth a retry rather than a terminal fail. Sourced from observed
// golang.org/x/net/http2 + net/http error message shapes when an
// upstream server kills the stream mid-response (INTERNAL_ERROR,
// REFUSED_STREAM, GOAWAY) or a network blip drops the connection.
//
// Owned by pkg/olium/stream as the leaf so both pkg/olium/engine
// (in-flight retry around streamOnce) and pkg/agent/retry
// (cross-call retry around runOliumPrompt) read the same list.
var TransientErrSubstrings = []string{
	"connection refused", "connection reset", "broken pipe",
	"i/o timeout", "tls handshake", "no such host",
	"unexpected eof", "use of closed network connection",
	"stream error", "internal_error", "refused_stream",
	"enhance_your_calm", "goaway", "http2:",
}

// IsTransientErr reports whether err's message matches any pattern in
// TransientErrSubstrings (case-insensitive substring).
func IsTransientErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range TransientErrSubstrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}
