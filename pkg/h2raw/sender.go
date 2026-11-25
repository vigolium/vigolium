// Package h2raw sends one HTTP/2 request with its frames written by hand, for
// framing probes the standard client refuses to send: a content-length header
// that disagrees with the DATA actually sent, a stream left open without
// END_STREAM, DATA split into chosen chunks. It measures how long the server
// takes to answer — the response HEADERS, a RST_STREAM or a GOAWAY — or that it
// did not answer within the timeout, which is the oracle of a timing-based
// desync probe (an incomplete body the server waits on).
//
// One request per connection, over TLS negotiated to h2 by ALPN (or cleartext
// prior knowledge with Cleartext). The connection is closed after the answer or
// the timeout, so a probe never leaves a poisoned connection behind.
package h2raw

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Request is one hand-framed HTTP/2 request.
type Request struct {
	Method    string // default GET
	Scheme    string // :scheme, default https (http with Cleartext)
	Authority string // :authority, default the dialed host
	Path      string // :path, default /
	// Headers are sent after the pseudo-headers, in order, names lowercased
	// as HTTP/2 requires.
	Headers [][2]string
	// ContentLength, when non-nil, is sent as the content-length header
	// whatever the body's real length — the mismatch is the probe.
	ContentLength *int64
	// Body is sent as DATA frames of at most ChunkSize bytes (0 = one frame).
	Body      []byte
	ChunkSize int
	// OpenStream leaves the stream open: the last frame carries no
	// END_STREAM, so a server that trusts content-length waits for bytes that
	// never come.
	OpenStream bool
}

// Options configure one send.
type Options struct {
	// Timeout bounds the wait for an answer after the last frame is written
	// (default 10s). Reaching it is a result (Result.TimedOut), not an error.
	Timeout time.Duration
	// DialTimeout bounds the TCP connect and TLS handshake (default 10s).
	DialTimeout time.Duration
	// TLSConfig is cloned for the handshake; NextProtos is forced to h2.
	// nil uses ServerName from the address and verifies the certificate.
	TLSConfig *tls.Config
	// Cleartext speaks h2c with prior knowledge instead of TLS.
	Cleartext bool
	// MaxBodyBytes caps the response body kept (default 64 KiB).
	MaxBodyBytes int
}

// Result is what the server did with the request.
type Result struct {
	// Answered is true when the server responded on the stream (HEADERS),
	// reset it, or closed the connection with GOAWAY before the timeout.
	Answered bool
	TimedOut bool
	// Elapsed runs from the last request frame written to the answer, or to
	// the timeout.
	Elapsed time.Duration
	Status  int
	Headers [][2]string
	Body    []byte
	// ResetCode is the RST_STREAM error code ("" when the stream was not
	// reset); GoAwayCode the GOAWAY error code ("" when none arrived).
	ResetCode  string
	GoAwayCode string
	// ALPN is the negotiated protocol ("h2c" for cleartext).
	ALPN string
}

// ErrNoH2 is returned when the server does not negotiate h2 by ALPN.
var ErrNoH2 = errors.New("h2raw: server did not negotiate h2")

const streamID = 1

// maxBodyBytes is HTTP/2's initial flow-control window (RFC 9113 §6.9.2): the
// most a client may send on a stream before the server grants more. The
// sender does not wait for WINDOW_UPDATE, so a probe body stays within it.
const maxBodyBytes = 65535

// Send dials addr (host:port), writes req's frames and waits for the answer.
func Send(ctx context.Context, addr string, req Request, opts Options) (Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 64 << 10
	}
	if len(req.Body) > maxBodyBytes {
		return Result{}, fmt.Errorf("h2raw: body of %d bytes exceeds the %d a stream may send before the server's first WINDOW_UPDATE", len(req.Body), maxBodyBytes)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return Result{}, fmt.Errorf("h2raw: address %q: %w", addr, err)
	}
	conn, alpn, err := dial(ctx, addr, host, opts)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return Result{}, fmt.Errorf("h2raw: preface: %w", err)
	}
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20}); err != nil {
		return Result{}, fmt.Errorf("h2raw: settings: %w", err)
	}

	block, err := encodeHeaders(req, host, opts.Cleartext)
	if err != nil {
		return Result{}, err
	}
	noBody := len(req.Body) == 0
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: block, EndHeaders: true,
		EndStream: noBody && !req.OpenStream,
	}); err != nil {
		return Result{}, fmt.Errorf("h2raw: headers: %w", err)
	}
	for _, chunk := range chunks(req.Body, req.ChunkSize) {
		last := len(chunk.rest) == 0
		if err := fr.WriteData(streamID, last && !req.OpenStream, chunk.data); err != nil {
			return Result{}, fmt.Errorf("h2raw: data: %w", err)
		}
	}
	sent := time.Now()
	res := Result{ALPN: alpn}
	_ = conn.SetReadDeadline(sent.Add(opts.Timeout))
	readAnswer(fr, conn, &res, opts.MaxBodyBytes)
	res.Elapsed = time.Since(sent)
	return res, nil
}

// readAnswer reads frames until the stream's answer completes, the server
// resets the stream or the connection, or the read deadline passes.
func readAnswer(fr *http2.Framer, conn net.Conn, res *Result, maxBody int) {
	var body bytes.Buffer
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				res.TimedOut = !res.Answered
			}
			res.Body = body.Bytes()
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.MetaHeadersFrame:
			if f.StreamID != streamID {
				continue
			}
			if !res.Answered {
				res.Answered = true
				for _, hf := range f.Fields {
					if hf.Name == ":status" {
						res.Status, _ = strconv.Atoi(hf.Value)
						continue
					}
					res.Headers = append(res.Headers, [2]string{hf.Name, hf.Value})
				}
			}
			if f.StreamEnded() {
				res.Body = body.Bytes()
				return
			}
		case *http2.DataFrame:
			if f.StreamID != streamID {
				continue
			}
			if n := len(f.Data()); n > 0 {
				if room := maxBody - body.Len(); room > 0 {
					body.Write(f.Data()[:min(n, room)])
				}
				// Return the flow-control credit so a large answer completes.
				_ = fr.WriteWindowUpdate(0, uint32(n))
				_ = fr.WriteWindowUpdate(streamID, uint32(n))
			}
			if f.StreamEnded() {
				res.Body = body.Bytes()
				return
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				res.Answered = true
				res.ResetCode = f.ErrCode.String()
				res.Body = body.Bytes()
				return
			}
		case *http2.GoAwayFrame:
			res.Answered = true
			res.GoAwayCode = f.ErrCode.String()
			res.Body = body.Bytes()
			return
		}
	}
}

func dial(ctx context.Context, addr, host string, opts Options) (net.Conn, string, error) {
	d := &net.Dialer{Timeout: opts.DialTimeout}
	if opts.Cleartext {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, "", fmt.Errorf("h2raw: dial: %w", err)
		}
		return c, "h2c", nil
	}
	cfg := &tls.Config{}
	if opts.TLSConfig != nil {
		cfg = opts.TLSConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	cfg.NextProtos = []string{http2.NextProtoTLS}
	td := &tls.Dialer{NetDialer: d, Config: cfg}
	c, err := td.DialContext(ctx, "tcp", addr)
	if err != nil {
		// RFC 7301 no_application_protocol (alert 120): a server that speaks
		// no protocol the client offered refuses the handshake outright.
		// crypto/tls surfaces a received alert only as text (an unexported
		// type behind a "remote error" net.OpError), so its fixed alert
		// string is what identifies it.
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "remote error" && strings.Contains(opErr.Err.Error(), "no application protocol") {
			return nil, "", fmt.Errorf("%w (%w)", ErrNoH2, err)
		}
		return nil, "", fmt.Errorf("h2raw: tls dial: %w", err)
	}
	tc := c.(*tls.Conn)
	if p := tc.ConnectionState().NegotiatedProtocol; p != http2.NextProtoTLS {
		_ = c.Close()
		return nil, "", fmt.Errorf("%w (negotiated %q)", ErrNoH2, p)
	}
	return c, http2.NextProtoTLS, nil
}

// encodeHeaders HPACK-encodes the pseudo-headers, the declared
// content-length and req.Headers.
func encodeHeaders(req Request, host string, cleartext bool) ([]byte, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
		if cleartext {
			scheme = "http"
		}
	}
	authority := req.Authority
	if authority == "" {
		authority = host
	}
	path := req.Path
	if path == "" {
		path = "/"
	}
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	write := func(name, value string) error {
		return enc.WriteField(hpack.HeaderField{Name: name, Value: value})
	}
	for _, kv := range [][2]string{{":method", method}, {":scheme", scheme}, {":authority", authority}, {":path", path}} {
		if err := write(kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	if req.ContentLength != nil {
		if err := write("content-length", strconv.FormatInt(*req.ContentLength, 10)); err != nil {
			return nil, err
		}
	}
	for _, h := range req.Headers {
		name := strings.ToLower(h[0])
		if name == "" || strings.HasPrefix(name, ":") || (name == "content-length" && req.ContentLength != nil) {
			continue
		}
		if err := write(name, h[1]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type chunk struct{ data, rest []byte }

// chunks splits body into DATA payloads of at most size bytes (0 = whole).
func chunks(body []byte, size int) []chunk {
	if len(body) == 0 {
		return nil
	}
	if size <= 0 || size > len(body) {
		size = len(body)
	}
	if size > 16384 { // the default SETTINGS_MAX_FRAME_SIZE
		size = 16384
	}
	var out []chunk
	for len(body) > 0 {
		n := min(size, len(body))
		out = append(out, chunk{data: body[:n], rest: body[n:]})
		body = body[n:]
	}
	return out
}
