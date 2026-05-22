package vigtool

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/replay"
)

const (
	// sendRawPerRunCap bounds total raw sockets the agent can open in one
	// run. Mirrors replay_request's ceiling — high enough to actually probe
	// a desync surface, low enough that a runaway loop can't hammer a host.
	sendRawPerRunCap = 200

	sendRawConnectTimeout = 10 * time.Second
	sendRawReadTimeout    = 10 * time.Second
	sendRawReadCapBytes   = 64 * 1024
	sendRawReadCapMax     = 1 * 1024 * 1024
)

// NewSendRawHTTPTool returns the send_raw_http tool — writes exact bytes to a
// TCP/TLS socket with zero net/http normalisation, so the agent can express
// request smuggling / desync / CRLF / malformed-request attacks that
// web_fetch and replay_request structurally cannot. Destinations are
// hard-blocked to the run's scope: an autonomous agent putting arbitrary
// bytes on an arbitrary socket is the most dangerous primitive in the
// toolkit, so it stays anchored to what the operator authorised.
func NewSendRawHTTPTool(ctx *ScanContext) tool.Tool {
	return &sendRawHTTPTool{ctx: ctx}
}

type sendRawHTTPTool struct {
	ctx      *ScanContext
	totalRun atomic.Int64
}

func (*sendRawHTTPTool) Name() string     { return "send_raw_http" }
func (*sendRawHTTPTool) Label() string    { return "Send raw HTTP" }
func (*sendRawHTTPTool) Category() string { return tool.CategoryVigolium }
func (*sendRawHTTPTool) IsReadOnly() bool { return false }
func (*sendRawHTTPTool) Description() string {
	return "Write exact bytes to a TCP/TLS socket with NO net/http normalisation — for request " +
		"smuggling, HTTP desync, CRLF/header injection, and malformed-request testing that web_fetch " +
		"and replay_request cannot express. Supply the full request line + headers + body verbatim " +
		"(use \\r\\n line endings). Optionally send a second request on the SAME connection to confirm " +
		"desync (the second response reflecting a smuggled prefix is the tell). Destinations are " +
		"hard-blocked to the run's scope. Capped at 200 sends per run."
}

func (*sendRawHTTPTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target": map[string]any{
				"type":        "string",
				"description": "Destination: scheme://host[:port] (e.g. https://app.example.com or http://app.example.com:8080). Must be in scope — out-of-scope hosts are rejected.",
			},
			"raw_request": map[string]any{
				"type":        "string",
				"description": "Exact request bytes. Include the request line, headers, blank line, and body. Use \\r\\n line endings. Sent verbatim — no header/Content-Length fixup.",
			},
			"second_request": map[string]any{
				"type":        "string",
				"description": "Optional second request sent on the SAME connection. Use to confirm smuggling/desync (a smuggled prefix surfaces in this request's response).",
			},
			"pipeline": map[string]any{
				"type":        "boolean",
				"description": "When true and second_request is set, write both requests back-to-back before reading (classic CL.TE/TE.CL pipelining). Default false: read the first response, then send the second.",
			},
			"tls": map[string]any{
				"type":        "boolean",
				"description": "Force TLS on/off. Default: inferred from scheme (https) or port (443).",
			},
			"tls_sni": map[string]any{
				"type":        "string",
				"description": "Override the TLS SNI / ServerName. Default: target host. Certificate verification is always skipped (testing tool).",
			},
			"connect_timeout_ms": map[string]any{
				"type":        "integer",
				"description": "TCP/TLS connect timeout in ms. Default 10000.",
			},
			"read_timeout_ms": map[string]any{
				"type":        "integer",
				"description": "Idle read timeout in ms — reading stops this long after the last byte. Default 10000.",
			},
			"read_cap_bytes": map[string]any{
				"type":        "integer",
				"description": fmt.Sprintf("Max response bytes to read per response. Default %d, max %d.", sendRawReadCapBytes, sendRawReadCapMax),
			},
			"normalize_newlines": map[string]any{
				"type":        "boolean",
				"description": "Convenience: rewrite all line endings to \\r\\n before sending. Default false (exact bytes — required for most desync payloads).",
			},
		},
		"required": []string{"target", "raw_request"},
	}
}

func (s *sendRawHTTPTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	if cur := s.totalRun.Load(); cur >= sendRawPerRunCap {
		return tool.Result{
			Content: fmt.Sprintf("send_raw_http rate-limited: %d sends this run (cap=%d). "+
				"If you still need to probe, halt and resume with a fresh run.", cur, sendRawPerRunCap),
			IsError: true,
		}, nil
	}

	target := argsString(args, "target")
	raw := stringArg(args, "raw_request")
	if target == "" || raw == "" {
		return tool.Result{Content: "send_raw_http: 'target' and 'raw_request' are both required", IsError: true}, nil
	}

	host, port, useTLS, perr := parseTarget(target, args)
	if perr != nil {
		return tool.Result{Content: "send_raw_http: " + perr.Error(), IsError: true}, nil
	}

	allowed := s.allowedHosts()
	if !hostInScope(host, allowed) {
		return tool.Result{
			Content: fmt.Sprintf(
				"send_raw_http: host %q is out of scope and was NOT sent. send_raw_http hard-blocks "+
					"out-of-scope destinations. In-scope hosts: [%s]. If this host is legitimately part "+
					"of the engagement, it must be added to the run's scope by the operator.",
				host, strings.Join(allowed, ", ")),
			IsError: true,
		}, nil
	}

	if argsBool(args, "normalize_newlines") {
		raw = normalizeCRLF(raw)
	}
	second := stringArg(args, "second_request")
	if second != "" && argsBool(args, "normalize_newlines") {
		second = normalizeCRLF(second)
	}

	connectTO := durationMs(args, "connect_timeout_ms", sendRawConnectTimeout)
	readTO := durationMs(args, "read_timeout_ms", sendRawReadTimeout)
	readCap := argsInt(args, "read_cap_bytes")
	if readCap <= 0 {
		readCap = sendRawReadCapBytes
	}
	if readCap > sendRawReadCapMax {
		readCap = sendRawReadCapMax
	}

	s.totalRun.Add(1)

	out := s.exchange(ctx, host, port, useTLS, sniFor(args, host), []byte(raw), []byte(second),
		argsBool(args, "pipeline"), connectTO, readTO, readCap)

	body, _ := json.Marshal(out)
	details := map[string]any{
		"target":            fmt.Sprintf("%s:%d", host, port),
		"response_bytes":    out.ResponseBytesTotal,
		"conn_closed_early": out.ConnClosedEarly,
		"two_request":       second != "",
	}
	if out.Error != "" {
		details["error"] = out.Error
	}
	return tool.Result{Content: string(body), Details: details}, nil
}

type rawExchangeResult struct {
	Target              string `json:"target"`
	TLS                 bool   `json:"tls"`
	SentBytes           int    `json:"sent_bytes"`
	SentEcho            string `json:"sent_echo"`
	SentTruncated       bool   `json:"sent_echo_truncated,omitempty"`
	Response            string `json:"response"`
	ResponseTruncated   bool   `json:"response_truncated,omitempty"`
	ResponseBytesTotal  int    `json:"response_bytes_total"`
	SecondResponse      string `json:"second_response,omitempty"`
	SecondResponseBytes int    `json:"second_response_bytes,omitempty"`
	ElapsedMs           int64  `json:"elapsed_ms"`
	ConnClosedEarly     bool   `json:"conn_closed_early"`
	Error               string `json:"error,omitempty"`
}

// exchange dials the socket, writes the exact bytes, and reads the raw
// response(s). Network errors land in result.Error (not a Go error) so the
// model always gets a structured reply it can reason about.
func (s *sendRawHTTPTool) exchange(ctx context.Context, host string, port int, useTLS bool, sni string,
	req, second []byte, pipeline bool, connectTO, readTO time.Duration, readCap int) *rawExchangeResult {

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	res := &rawExchangeResult{Target: addr, TLS: useTLS, SentBytes: len(req) + len(second)}
	sentEcho, sentTrunc := clipBytes(req, replay.DefaultExcerptCap)
	res.SentEcho, res.SentTruncated = sentEcho, sentTrunc

	start := time.Now()
	defer func() { res.ElapsedMs = time.Since(start).Milliseconds() }()

	d := net.Dialer{Timeout: connectTO}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Error = fmt.Sprintf("dial %s: %v", addr, err)
		return res
	}
	conn := net.Conn(rawConn)
	defer func() { _ = conn.Close() }()

	if useTLS {
		tconn := tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // testing tool: target certs are often self-signed/invalid by design
			ServerName:         sni,
		})
		hsCtx, cancel := context.WithTimeout(ctx, connectTO)
		defer cancel()
		if err := tconn.HandshakeContext(hsCtx); err != nil {
			res.Error = fmt.Sprintf("tls handshake %s: %v", addr, err)
			return res
		}
		conn = tconn
	}

	write := func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		_ = conn.SetWriteDeadline(time.Now().Add(connectTO))
		_, werr := conn.Write(b)
		return werr
	}

	if pipeline && len(second) > 0 {
		// Write both before reading — CL.TE / TE.CL pipelining.
		if err := write(req); err != nil {
			res.Error = fmt.Sprintf("write request 1: %v", err)
			return res
		}
		if err := write(second); err != nil {
			res.Error = fmt.Sprintf("write request 2: %v", err)
			return res
		}
		buf, closed := readRaw(conn, readTO, readCap)
		res.Response, res.ResponseTruncated = clipBytes(buf, readCap)
		res.ResponseBytesTotal = len(buf)
		res.ConnClosedEarly = closed
		return res
	}

	if err := write(req); err != nil {
		res.Error = fmt.Sprintf("write request: %v", err)
		return res
	}
	buf, closed := readRaw(conn, readTO, readCap)
	res.Response, res.ResponseTruncated = clipBytes(buf, readCap)
	res.ResponseBytesTotal = len(buf)
	res.ConnClosedEarly = closed

	if len(second) > 0 {
		if closed {
			res.Error = "connection closed before second request could be sent (no keep-alive)"
			return res
		}
		if err := write(second); err != nil {
			res.Error = fmt.Sprintf("write request 2: %v", err)
			return res
		}
		buf2, closed2 := readRaw(conn, readTO, readCap)
		res.SecondResponse, _ = clipBytes(buf2, readCap)
		res.SecondResponseBytes = len(buf2)
		res.ConnClosedEarly = closed2
	}
	return res
}

// readRaw reads until the peer closes, the idle read deadline elapses, or the
// cap is hit. A deadline hit is normal termination (keep-alive connections
// never EOF) and is not treated as an error; closed reports a clean peer EOF.
func readRaw(conn net.Conn, idle time.Duration, limit int) (out []byte, closed bool) {
	buf := make([]byte, 16*1024)
	for len(out) < limit {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, err := conn.Read(buf)
		if n > 0 {
			room := limit - len(out)
			if n > room {
				n = room
			}
			out = append(out, buf[:n]...)
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return out, false // idle timeout: done reading, conn still open
			}
			// io.EOF or any other read error: peer is done with us.
			return out, true
		}
	}
	return out, false
}

// allowedHosts derives the in-scope host allowlist from the run's primary
// target plus any host-like scope entries. Empty means "block everything" —
// raw-send without an authorised network target is meaningless anyway.
func (s *sendRawHTTPTool) allowedHosts() []string {
	if s.ctx == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	add(hostOf(s.ctx.Target))
	for _, sc := range s.ctx.Scope {
		add(hostOf(sc))
	}
	return out
}

// hostOf extracts a bare hostname from a URL, host:port, or bare-host string.
// Returns "" for entries that aren't host-like (free-text scope notes).
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// Reject obvious non-host tokens (paths, sentences, globs).
	if strings.ContainsAny(s, " \t/\\*?") {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(s)
}

func hostInScope(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if host == a {
			return true
		}
	}
	return false
}

// parseTarget resolves host, port, and TLS from the target string + optional
// overrides. Accepts scheme://host[:port], host:port, or bare host.
func parseTarget(target string, args map[string]any) (host string, port int, useTLS bool, err error) {
	t := strings.TrimSpace(target)
	var scheme string
	if strings.Contains(t, "://") {
		u, perr := url.Parse(t)
		if perr != nil || u.Hostname() == "" {
			return "", 0, false, fmt.Errorf("invalid target URL %q", target)
		}
		scheme = strings.ToLower(u.Scheme)
		host = u.Hostname()
		if p := u.Port(); p != "" {
			_, _ = fmt.Sscanf(p, "%d", &port)
		}
	} else if h, p, serr := net.SplitHostPort(t); serr == nil {
		host = h
		_, _ = fmt.Sscanf(p, "%d", &port)
	} else {
		host = t
	}
	if host == "" {
		return "", 0, false, fmt.Errorf("could not determine host from %q", target)
	}

	switch scheme {
	case "https":
		useTLS = true
	case "http":
		useTLS = false
	default:
		useTLS = port == 443
	}
	if v, ok := args["tls"].(bool); ok {
		useTLS = v
	}
	if port == 0 {
		if useTLS {
			port = 443
		} else {
			port = 80
		}
	}
	return host, port, useTLS, nil
}

func sniFor(args map[string]any, host string) string {
	if v := argsString(args, "tls_sni"); v != "" {
		return v
	}
	return host
}

// stringArg reads a string without trimming — raw_request / second_request
// must preserve leading/trailing whitespace and exact line endings.
func stringArg(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

func durationMs(args map[string]any, key string, def time.Duration) time.Duration {
	if v := argsInt(args, key); v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return def
}

// normalizeCRLF rewrites all line endings to \r\n. Convenience only — most
// desync payloads need exact bytes and must not use this.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}
