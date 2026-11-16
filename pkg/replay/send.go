package replay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/proxytarget"
)

const (
	// defaultUserAgent is set when the raw request didn't carry one;
	// some WAFs reject empty UA outright and we'd waste turns debugging
	// the resulting 403 vs the real baseline.
	defaultUserAgent = "Mozilla/5.0 (vigolium-replay)"

	defaultMaxResponseBytes = 5 * 1024 * 1024

	// DefaultTimeout is the per-request wall-clock budget used by
	// NewDefaultClient when callers don't supply one.
	DefaultTimeout = 25 * time.Second
)

// NewDefaultClient is NewClient routed by the environment's proxy
// (proxyenv: HTTPS_PROXY / HTTP_PROXY / ALL_PROXY by scheme, NO_PROXY
// honoured), resolved once here.
func NewDefaultClient(jar gohttp.CookieJar, timeout time.Duration) *gohttp.Client {
	return NewClient(jar, timeout, proxyenv.FromEnvironment(""))
}

// NewClient returns an *http.Client suitable for replay traffic, routed by
// proxy (direct when it names none). TLS verification is off because targets
// are often localhost or self-signed staging. The transport is a
// proxytarget.Transport, so a request whose Host header differs from its
// destination still reaches an HTTP proxy addressed to the destination's
// host:port. Pass jar=nil for stateless replays.
func NewClient(jar gohttp.CookieJar, timeout time.Duration, proxy proxyenv.Choice) *gohttp.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &gohttp.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: proxytarget.Wrap(&gohttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ClientSessionCache: network.TLSSessionCache()}, //nolint:gosec // intentional for replay
			Proxy:           proxy.Func(),
		}),
	}
}

// isDefaultPort reports whether port is the well-known default for scheme and
// can therefore be omitted from an authority.
func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// Authority returns the URL authority for a destination: host:port, with the
// port omitted when it is zero or the scheme's default (80 for http, 443 for
// https; an empty scheme means http). An IPv6 literal is bracketed whether or
// not a port follows, and hostname may arrive bracketed already.
func Authority(scheme, hostname string, port int) string {
	if scheme == "" {
		scheme = "http"
	}
	host := strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")
	if port > 0 && !isDefaultPort(strings.ToLower(scheme), port) {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// sendRawHTTP parses raw request bytes, points the request at the supplied
// scheme/hostname/port, and sends via client. A *Summary is returned even on
// transport error so callers always get a structured response. noRedirects
// clones the client to avoid mutating shared redirect policy across calls.
//
// The destination (the connection, and the absolute-form target an HTTP proxy
// receives) is always scheme://Authority(scheme, hostname, port). The Host
// header is the raw request's own, sent as written, so a fuzzed or mutated
// Host and a request replayed against another environment keep the Host the
// caller wrote — the same bytes the Burp-bridge Sender sends. A raw request
// with no Host header gets the destination's authority. Through an HTTP proxy
// a Host that differs from the destination relies on the client's transport
// being a proxytarget.Transport (NewDefaultClient's is).
func sendRawHTTP(ctx context.Context, client *gohttp.Client, raw []byte, scheme, hostname string, port int, noRedirects bool, excerptCap int) *Summary {
	return sendRawHTTPWith(ctx, client, raw, sendTarget{scheme: scheme, hostname: hostname, port: port}, noRedirects, excerptCap)
}

// sendTarget is where sendRawHTTPWith sends, and how exactly.
type sendTarget struct {
	scheme, hostname string
	port             int
	// exact sends the bytes as given: no User-Agent is added and the
	// transport adds no Accept-Encoding (--raw-request).
	exact bool
}

func sendRawHTTPWith(ctx context.Context, client *gohttp.Client, raw []byte, t sendTarget, noRedirects bool, excerptCap int) *Summary {
	scheme, hostname, port := t.scheme, t.hostname, t.port
	if excerptCap <= 0 {
		excerptCap = DefaultExcerptCap
	}

	req, err := gohttp.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return &Summary{Error: fmt.Sprintf("parse request: %v", err)}
	}
	defer func() {
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
	}()

	if scheme == "" {
		scheme = "http"
	}
	// RawPath must be carried over, not just Path. Path is the *decoded*
	// target, so rebuilding the URL without RawPath re-encodes it from
	// scratch and silently normalizes percent-escapes on the wire —
	// "/a/..%2fadmin" would leave as "/a/../admin" and "/%2e%2e/x" as
	// "/../x". For a scanner those escapes are the payload: they're exactly
	// what distinguishes a proxy-normalization bypass probe from a plain
	// traversal. net/http emits RawPath verbatim whenever it's a valid
	// encoding of Path, so preserving it keeps the operator's bytes intact.
	// ForceQuery keeps a bare trailing "?" from being dropped.
	req.URL = &url.URL{
		Scheme:     scheme,
		Host:       Authority(scheme, hostname, port),
		Path:       req.URL.Path,
		RawPath:    req.URL.RawPath,
		RawQuery:   req.URL.RawQuery,
		ForceQuery: req.URL.ForceQuery,
	}
	// req.Host already holds the raw Host header (ReadRequest moves it there);
	// when it is empty net/http sends req.URL.Host, the destination authority.
	req.RequestURI = ""

	if t.exact {
		// net/http adds a Go User-Agent to a request without one; an empty
		// value keeps it off the wire.
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header["User-Agent"] = []string{""}
		}
	} else if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	// One client per send, a copy of the caller's: it counts the redirects it
	// follows, and an exact send uses a transport that adds no
	// Accept-Encoding. The caller's redirect policy (fuzz --max-redirs) still
	// decides when to stop, the replay default when it has none.
	hops := 0
	policy := client.CheckRedirect
	if policy == nil {
		policy = RedirectLimit(maxReplayRedirects)
	}
	sendClient := *client
	sendClient.CheckRedirect = func(next *gohttp.Request, via []*gohttp.Request) error {
		if noRedirects {
			return gohttp.ErrUseLastResponse
		}
		if err := policy(next, via); err != nil {
			return err
		}
		hops = len(via)
		return nil
	}
	if t.exact {
		sendClient.Transport = uncompressedTransport(client.Transport)
	}

	req = req.WithContext(ctx)
	var reqDump []byte
	if TrafficDump != nil {
		reqDump, _ = httputil.DumpRequestOut(req, true)
	}
	start := time.Now()
	resp, err := sendClient.Do(req)
	elapsed := time.Since(start)
	if TrafficDump != nil {
		dumpExchange(req, reqDump, resp, err, elapsed)
	}
	if err != nil {
		return &Summary{
			Error:          fmt.Sprintf("request failed: %v", err),
			ResponseTimeMs: elapsed.Milliseconds(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponseBytes))
	sum := sha256.Sum256(bodyBytes)
	excerpt, truncated := clipBytes(bodyBytes, excerptCap)
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	out := &Summary{
		FinalURL:       finalURL,
		Status:         resp.StatusCode,
		ResponseLen:    len(bodyBytes),
		ContentHash:    hex.EncodeToString(sum[:8]),
		ResponseTimeMs: elapsed.Milliseconds(),
		Headers:        resp.Header,
		Excerpt:        excerpt,
		Truncated:      truncated,
		RawBody:        bodyBytes,
	}
	if hops > 0 {
		out.Redirects = hops
	}
	return out
}

// maxReplayRedirects is how many redirects a replay follows (net/http's own
// default).
const maxReplayRedirects = 10

// RedirectLimit is a CheckRedirect policy that stops after n requests in a
// redirect chain (net/http's counting: the first request included).
func RedirectLimit(n int) func(*gohttp.Request, []*gohttp.Request) error {
	return func(_ *gohttp.Request, via []*gohttp.Request) error {
		if len(via) >= n {
			return fmt.Errorf("stopped after %d redirects", n)
		}
		return nil
	}
}

// uncompressedTransport is rt with DisableCompression set, so the transport
// adds no Accept-Encoding. rt is returned unchanged when it is not an
// *http.Transport underneath.
func uncompressedTransport(rt gohttp.RoundTripper) gohttp.RoundTripper {
	base, ok := proxytarget.Base(rt)
	if !ok {
		return rt
	}
	clone := base.Clone()
	clone.DisableCompression = true
	if _, wrapped := rt.(*proxytarget.Transport); wrapped {
		return proxytarget.Wrap(clone)
	}
	return clone
}

// TrafficDump, when set, receives every exchange replay sends (--dump-traffic).
// reqDump is the request as sent; resp's body has not been read yet.
var TrafficDump func(method, url string, reqDump []byte, resp *gohttp.Response, err error, elapsed time.Duration)

func dumpExchange(req *gohttp.Request, reqDump []byte, resp *gohttp.Response, err error, elapsed time.Duration) {
	TrafficDump(req.Method, req.URL.String(), reqDump, resp, err, elapsed)
}

// SendRaw sends raw request bytes against scheme://hostname:port using
// client and returns a structured *Summary (populated even on transport
// error, so callers always get something to inspect). It is the exact
// send + body-capture + hashing path Do() uses internally; it is exported
// so sibling engines — notably pkg/fuzz — can reuse it without reimplementing
// request parsing, redirect handling, or response hashing. Pass excerptCap=0
// for DefaultExcerptCap.
func SendRaw(ctx context.Context, client *gohttp.Client, raw []byte, scheme, hostname string, port int, noRedirects bool, excerptCap int) *Summary {
	return sendRawHTTP(ctx, client, raw, scheme, hostname, port, noRedirects, excerptCap)
}

// Do applies mutations (or the raw override), overlays headers, sends,
// and returns a baseline-vs-replay Result.
//
// Errors signal configuration/parse problems; network failures land in
// result.Replay.Error so callers always get a structured response they
// can show the operator or feed to an LLM.
//
// Caller responsibilities not handled here: rate limiting, project/scope
// enforcement, cookie persistence between calls (provide a jar on
// opts.Client), persisting the replay back to DB.
func Do(ctx context.Context, opts Options) (*Result, error) {
	if opts.Client == nil && opts.Sender == nil {
		return nil, fmt.Errorf("replay.Do: opts.Client or opts.Sender is required")
	}
	if len(opts.BaselineRequest) == 0 && len(opts.RawRequest) == 0 {
		return nil, fmt.Errorf("replay.Do: BaselineRequest or RawRequest is required")
	}
	if opts.Hostname == "" {
		return nil, fmt.Errorf("replay.Do: Hostname is required")
	}

	excerptCap := opts.ExcerptCap
	if excerptCap <= 0 {
		excerptCap = DefaultExcerptCap
	}

	var (
		mutated          []byte
		payloads         []string
		unmatched        []string
		additionalGroups int
	)
	switch {
	case len(opts.RawRequest) > 0:
		mutated = opts.RawRequest
	case len(opts.Mutations) > 0:
		m, p, u, ag, err := applyMutations(opts.BaselineRequest, opts.Mutations)
		if err != nil {
			return nil, err
		}
		mutated, payloads, unmatched, additionalGroups = m, p, u, ag
	default:
		// No mutations, no override — replay the baseline verbatim.
		// Useful for re-checking a stored record under fresh cookies.
		mutated = opts.BaselineRequest
	}

	if len(opts.HeaderOverlay) > 0 {
		mutated = overlayHeaders(mutated, opts.HeaderOverlay)
	}

	// send routes one request through the caller's Sender (e.g. the Burp bridge)
	// when set, else the built-in net/http path — so via-Burp and native replays
	// share the identical baseline/replay/diff logic below.
	send := func(raw []byte) *Summary {
		if opts.Sender != nil {
			return opts.Sender(ctx, raw)
		}
		return sendRawHTTPWith(ctx, opts.Client, raw, sendTarget{
			scheme: opts.Scheme, hostname: opts.Hostname, port: opts.Port,
			exact: len(opts.RawRequest) > 0,
		}, opts.NoRedirects, excerptCap)
	}

	sentReq, sentTrunc := clipBytes(mutated, excerptCap)

	var baseline *Summary
	switch {
	case len(opts.BaselineResponse) > 0:
		baseline = baselineFromResponse(opts.BaselineResponse, opts.BaselineStatus, opts.BaselineResponseTime, excerptCap)
	case len(opts.BaselineRequest) > 0 && !opts.SendBaseline && bytes.Equal(mutated, opts.BaselineRequest):
		// The request is its own baseline: send it once, with nothing to diff.
		return &Result{
			MutatedRequest:      sentReq,
			MutatedRequestTrunc: sentTrunc,
			Replay:              send(mutated),
			AdditionalGroups:    additionalGroups,
			Unmatched:           unmatched,
			RawMutatedRequest:   append([]byte(nil), mutated...),
		}, nil
	case len(opts.BaselineRequest) > 0:
		baseline = send(opts.BaselineRequest)
	default:
		baseline = &Summary{}
	}

	replay := send(mutated)
	diff := computeDiff(baseline, replay, payloads)
	if opts.BaselineIsEvidence && diff != nil && strings.HasPrefix(diff.Interpretation, "response identical to baseline") {
		diff.Interpretation = "response identical to the finding's evidence: the finding reproduced."
	}

	return &Result{
		MutatedRequest:      sentReq,
		MutatedRequestTrunc: sentTrunc,
		Baseline:            baseline,
		Replay:              replay,
		Diff:                diff,
		AdditionalGroups:    additionalGroups,
		Unmatched:           unmatched,
		RawMutatedRequest:   append([]byte(nil), mutated...),
	}, nil
}
