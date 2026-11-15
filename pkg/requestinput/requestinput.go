// Package requestinput turns raw HTTP request text into the request to send,
// with one normalization and one scheme rule for every command that takes a
// request as text (scan-request, replay -i, fuzz -i):
//
//   - Normalize: leading whitespace is dropped; a request that declares no
//     body (no Content-Length, no Transfer-Encoding) loses its trailing
//     whitespace and gets exactly one header terminator, so text pasted with
//     the final blank line stripped, or read from a line-trimming stdin,
//     parses and sends. A body-bearing request keeps its bytes.
//   - Scheme: a target override (-t) pins scheme, host and port; otherwise an
//     absolute request line, a Host on :80/:443, or a same-origin Origin or
//     Referer settles it; failing those the target is probed (TCP connect, TLS
//     handshake) unless the caller turns the probe off, and https is the
//     default (requestscheme.Settle).
package requestinput

import (
	"context"
	"errors"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/requestscheme"
)

// Options tune Parse.
type Options struct {
	// Target is the -t override: the base URL whose scheme, host and port the
	// request goes to. It pins the scheme (no probe).
	Target string
	// NoProbe keeps the inferred default instead of probing the target.
	NoProbe bool
	// Resolver replaces the scheme probe (tests). Nil = the real probe.
	Resolver requestscheme.Resolver
}

// Result is a parsed request.
type Result struct {
	// Request is the request to send, its URL settled.
	Request *httpmsg.HttpRequestResponse
	// Raw is the normalized request text, header terminator included: the
	// bytes a raw sender writes.
	Raw string
	// Parsed is the text the parser read (Raw without a bodyless request's
	// terminator), what requestscheme and a re-parse expect.
	Parsed string
	// SchemeSource says what settled the scheme (requestscheme.Source*).
	SchemeSource string
	// Scheme is the result of requestscheme.Settle, for callers that report
	// how the scheme was chosen.
	Scheme requestscheme.Result
}

// ErrEmpty is returned for input with no request text.
var ErrEmpty = errors.New("empty request input")

// Normalize returns the text to parse and the bytes to send for raw. See the
// package comment.
func Normalize(raw string) (parsed, send string) {
	raw = strings.TrimLeft(raw, " \t\r\n")
	if DeclaresBody(raw) {
		if !strings.Contains(raw, "\r\n\r\n") && !strings.Contains(raw, "\n\n") {
			raw += "\r\n\r\n"
		}
		return raw, raw
	}
	trimmed := strings.TrimRight(raw, " \t\r\n")
	if trimmed == "" {
		return "", ""
	}
	return trimmed, trimmed + "\r\n\r\n"
}

// DeclaresBody reports whether the header block of raw carries a
// Content-Length or Transfer-Encoding header. Only the header block is
// scanned, case-insensitively at the start of a line.
func DeclaresBody(raw string) bool {
	head := raw
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head = head[:i]
	} else if i := strings.Index(head, "\n\n"); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(head, "\n") {
		name := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(name, "content-length:") || strings.HasPrefix(name, "transfer-encoding:") {
			return true
		}
	}
	return false
}

// Parse normalizes raw, parses it and settles its scheme.
func Parse(ctx context.Context, raw string, opts Options) (Result, error) {
	parsed, send := Normalize(raw)
	if parsed == "" {
		return Result{}, ErrEmpty
	}
	var (
		rr  *httpmsg.HttpRequestResponse
		err error
	)
	target := strings.TrimSpace(opts.Target)
	if target != "" {
		rr, err = httpmsg.ParseRawRequestWithURL(parsed, target)
	} else {
		rr, err = httpmsg.ParseRawRequest(parsed)
	}
	if err != nil {
		return Result{}, err
	}
	res := requestscheme.Settle(ctx, parsed, rr, requestscheme.Options{
		Pinned:   target != "",
		NoProbe:  opts.NoProbe,
		Resolver: opts.Resolver,
	})
	return Result{Request: res.Request, Raw: send, Parsed: parsed, SchemeSource: res.Source, Scheme: res}, nil
}
